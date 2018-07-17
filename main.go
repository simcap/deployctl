package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"os/exec"
	"errors"
)

var (
	cliHome        = filepath.Join(os.Getenv("HOME"), ".deployd")
	configFilepath = filepath.Join(cliHome, "config.json")

	targetFlag, userFlag, proxyFlag, keyFlag           string
	envFlag, serviceNameFlag, rootDirFlag, binFileFlag string
	logLinesCount                                      int
	tailOption                                         bool

	logsCmd   = flag.NewFlagSet("logs", flag.ExitOnError)
	deployCmd = flag.NewFlagSet("deploy", flag.ExitOnError)
	buildCmd = flag.NewFlagSet("build", flag.ExitOnError)
)

func init() {
	flag.StringVar(&envFlag, "env", "", fmt.Sprintf("Specify an env defined in the config file %s", configFilepath))
	flag.StringVar(&targetFlag, "h", "", "ssh hostname")
	flag.StringVar(&proxyFlag, "proxy", "", "ssh proxy (i.e. jump server, bastion, etc.)")
	flag.StringVar(&userFlag, "u", "", "ssh user")
	flag.StringVar(&serviceNameFlag, "s", "", "Name of the systemd service")
	flag.StringVar(&rootDirFlag, "r", "", "Full path of the root directory on the remote (contains all services dirs)")

	deployCmd.StringVar(&binFileFlag, "bin", "", "Filepath of the service binary file")

	logsCmd.IntVar(&logLinesCount, "n", 10, "Show the last n journalctl logs line")
	logsCmd.BoolVar(&tailOption, "f", false, "Tail and follow the logs")
}

func main() {
	log.SetFlags(0)
	flag.Parse()

	if serviceNameFlag == "" {
		log.Fatal("missing -s flag name of service")
	}

	conf, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	if serviceNameFlag == "" {
		log.Fatal("missing -s flag name of service")
	}

	if len(envFlag) > 0 {
		ok, env := conf.getEnv(envFlag)
		if !ok {
			log.Fatalf("env %s is not define in config file %s", envFlag, configFilepath)
		}
		mergeFlagAndConfigEnv(env)
	}

	switch  flag.Arg(0) {
	case "build":
		if _, err := buildBinary(); err != nil {
			log.Fatal(err)
		}
		return
	}

	client := connect()
	defer client.Close()

	switch  flag.Arg(0) {
	case "deploy":
		deployCmd.Parse(flag.Args()[1:])
		if binFileFlag == "" {
			var err error
			binFileFlag, err = buildBinary()
			if err != nil {
				log.Fatal(err)
			}
		}
		session, err := client.NewSession()
		if err != nil {
			log.Fatal(err)
		}
		if err := copyFile(session, binFileFlag); err != nil {
			log.Fatal(err)
		}
	case "logs":
		logsCmd.Parse(flag.Args()[1:])
		if tailOption {
			run(client, fmt.Sprintf("sudo journalctl -fu %s", serviceNameFlag))
			return
		}
		run(client, fmt.Sprintf("sudo journalctl -n %d -u %s", logLinesCount, serviceNameFlag))
	default:
		run(client, fmt.Sprintf("systemctl status %s", serviceNameFlag))
	}
}

type Config struct {
	Envs map[string]*Env
}

func (c Config) getEnv(name string) (bool, *Env) {
	for n, env := range c.Envs {
		if n == name {
			return true, env
		}
	}
	return false, nil
}

type Env struct {
	Host    string
	Proxy   string
	RootDir string
	User    string
}

func buildBinary() (string, error) {
	if _, err := exec.LookPath("go"); err != nil {
		return "", errors.New("cannot build binary as 'go' command not found")
	}
	if _, err := exec.LookPath("git"); err != nil {
		return "", errors.New("missing 'git' command to get HEAD sha")
	}

	goVersion, err := exec.Command("go", "version").Output()
	if err != nil {
		return "", err
	}
	goVersion = bytes.TrimSpace(goVersion)


	sha, err := exec.Command("git", "rev-parse", "--short", "HEAD").Output()
	if err != nil {
		return "", err
	}
	sha = bytes.TrimSpace(sha)

	goos := "GOOS=linux"
	binName := fmt.Sprintf("%s-%s", serviceNameFlag, sha)
	buildCmd := exec.Command("go", "build", "-o", binName)
	buildCmd.Env = append(os.Environ(), goos)

	log.Printf("executing %s with %s for %s", buildCmd.Args, goos, goVersion)
	return binName, buildCmd.Run()
}

func loadConfig() (Config, error) {
	var conf Config
	if _, err := os.Stat(configFilepath); os.IsNotExist(err) {
		return conf, nil
	}

	f, err := os.Open(configFilepath)
	if err != nil {
		return conf, nil
	}
	if err := json.NewDecoder(f).Decode(&conf); err != nil {
		return conf, fmt.Errorf("cannot unmarshal json config file at %s: %s", configFilepath, err)
	}
	return conf, nil
}

func mergeFlagAndConfigEnv(env *Env) {
	if len(env.Host) > 0 {
		targetFlag = env.Host
	}
	if len(env.Proxy) > 0 {
		proxyFlag = env.Proxy
	}
	if len(env.User) > 0 {
		userFlag = env.User
	}
	if len(env.RootDir) > 0 {
		rootDirFlag = env.RootDir
	}
}

func copyFile(session *ssh.Session, filepath string) error {
	defer session.Close()

	f, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}

	w, err := session.StdinPipe()
	if err != nil {
		return err
	}
	defer w.Close()

	if err := session.Start("scp -t /tmp"); err != nil {
		w.Close()
		return err
	}

	fmt.Fprintf(w, "C%#o %d %s\n", info.Mode().Perm(), info.Size(), path.Base(filepath))
	io.Copy(w, f)
	fmt.Fprint(w, "\x00")
	w.Close()

	return session.Wait()
}

func run(client *ssh.Client, cmd string) {
	fmt.Printf("\033[32m$ %s\033[m\n", cmd)
	session, err := client.NewSession()
	if err != nil {
		log.Fatalf("new session on open conn: %s", err)
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	if err != nil {
		fmt.Println(identText(out))
		log.Fatal(err)
	}
	fmt.Println(identText(out))
}

func identText(b []byte) string {
	return fmt.Sprintf("\t%s", bytes.Replace(b, []byte("\n"), []byte("\n\t"), -1))
}

func connect() *ssh.Client {
	var auths []ssh.AuthMethod
	if a, err := agentAuth(); err == nil {
		auths = append(auths, a)
	} else {
		log.Fatal(err)
	}

	conf := &ssh.ClientConfig{
		User:            userFlag,
		Auth:            auths,
		Timeout:         10 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	proxyHostPort := fmt.Sprintf("%s:22", proxyFlag)
	log.Printf("dialing %s@%s", userFlag, proxyHostPort)
	conn, err := ssh.Dial("tcp", proxyHostPort, conf)
	if err != nil {
		log.Fatal(err)
	}

	targetHostPort := fmt.Sprintf("%s:22", targetFlag)
	fullConn, err := conn.Dial("tcp", targetHostPort)
	if err != nil {
		log.Fatalf("cannot dial from %s to %s", proxyFlag, targetFlag)
	}
	log.Printf("successful tcp connection from %s to %s", proxyFlag, targetFlag)

	finalConn, chans, reqs, err := ssh.NewClientConn(fullConn, targetHostPort, conf)
	if err != nil {
		fullConn.Close()
		log.Fatalf("cannot proxy with user %s (err: %s)", userFlag, err)
	}
	log.Printf("proxied successfully with user %s", userFlag)

	return ssh.NewClient(finalConn, chans, reqs)
}

func agentAuth() (ssh.AuthMethod, error) {
	sock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeysCallback(agent.NewClient(sock).Signers), nil
}
