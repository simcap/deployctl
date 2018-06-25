package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var (
	targetFlag, userFlag, proxyFlag, keyFlag string

	serviceNameFlag string
)

func init() {
	flag.StringVar(&targetFlag, "h", "", "ssh hostname")
	flag.StringVar(&proxyFlag, "proxy", "", "ssh proxy (i.e. jump server, bastion, etc.)")
	flag.StringVar(&userFlag, "u", "", "ssh user")
	flag.StringVar(&serviceNameFlag, "s", "", "Name of the systemd service")
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	client := connect()
	defer client.Close()

	run(client, fmt.Sprintf("systemctl status %s", serviceNameFlag))
	run(client, fmt.Sprintf("sudo journalctl -u %s", serviceNameFlag))
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
