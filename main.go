package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	cliHome        = filepath.Join(os.Getenv("HOME"), ".deployd")
	configFilepath = filepath.Join(cliHome, "config.json")

	targetFlag, userFlag, proxyFlag, keyFlag string
	envFlag, serviceNameFlag, rootDirFlag    string
	logLinesCount                            int
	tailOption                               bool

	logsCmd = flag.NewFlagSet("logs", flag.ExitOnError)
)

func init() {
	flag.StringVar(&envFlag, "env", "", fmt.Sprintf("Specify an env defined in the config file %s", configFilepath))
	flag.StringVar(&targetFlag, "h", "", "ssh hostname")
	flag.StringVar(&proxyFlag, "proxy", "", "ssh proxy (i.e. jump server, bastion, etc.)")
	flag.StringVar(&userFlag, "u", "", "ssh user")
	flag.StringVar(&serviceNameFlag, "s", "", "Name of the systemd service")
	flag.StringVar(&rootDirFlag, "r", "", "Full path of the root directory on the remote (contains all services dirs)")

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

	client := connect()
	defer client.Close()

	switch flag.Arg(0) {
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
