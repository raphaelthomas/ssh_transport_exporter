// Command probetest runs a single probe against a target and prints the
// result. Useful for iterating on pkg/probe directly without going
// through the HTTP exporter.
//
// Usage:
//
//	go run ./cmd/probetest -known-hosts ~/.ssh/known_hosts host:22
//	go run ./cmd/probetest -timeout 2s host:22   # WARNING: skips host key verification
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/raphaelthomas/ssh_transport_exporter/pkg/probe"
)

func main() {
	timeout := flag.Duration("timeout", 5*time.Second, "probe timeout")
	knownHostsPath := flag.String("known-hosts", "", "path to known_hosts file (omit to skip host key verification)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: probetest [-timeout 5s] [-known-hosts path] host:port")
		os.Exit(2)
	}
	target := flag.Arg(0)

	var hostKeyCallback ssh.HostKeyCallback
	if *knownHostsPath == "" {
		fmt.Fprintln(os.Stderr, "WARNING: no -known-hosts given, host key verification is DISABLED (dev-only mode)")
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	} else {
		var err error
		hostKeyCallback, err = knownhosts.New(*knownHostsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "loading known_hosts file: %v\n", err)
			os.Exit(2)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	start := time.Now()
	result := probe.Run(ctx, target, probe.Options{HostKeyCallback: hostKeyCallback})
	elapsed := time.Since(start)

	fmt.Printf("target:               %s\n", target)
	fmt.Printf("tcp_connect_success:  %v\n", result.TCPConnectSuccess)
	if result.TCPConnectSuccess {
		fmt.Printf("tcp_connect_duration: %s\n", result.TCPConnectDuration)
		if result.TCPConnectNegotiatedMSS > 0 {
			fmt.Printf("tcp_negotiated_mss:   %d\n", result.TCPConnectNegotiatedMSS)
		}
	}
	if result.ServerVersion != "" {
		fmt.Printf("server_version:       %s\n", result.ServerVersion)
	}
	fmt.Printf("kex_success:          %v\n", result.KEXSuccess)
	if result.KEXSuccess {
		fmt.Printf("kex_duration:         %s\n", result.KEXDuration)
		fmt.Printf("kex_algorithm:        %s\n", result.KEXAlgorithm)
	}
	fmt.Printf("host_key_success:     %v\n", result.HostKeyVerifySuccess)
	if result.HostKeyAlgorithm != "" {
		fmt.Printf("host_key_algorithm:   %s\n", result.HostKeyAlgorithm)
	}
	if result.CipherRead != "" || result.CipherWrite != "" {
		fmt.Printf("cipher_read:          %s\n", result.CipherRead)
		fmt.Printf("cipher_write:         %s\n", result.CipherWrite)
	}
	if result.ErrorStage != "" {
		fmt.Printf("error_stage:          %s\n", result.ErrorStage)
		fmt.Printf("error_reason:         %s\n", result.ErrorReason)
	}
	fmt.Printf("total_elapsed:        %s\n", elapsed)

	if result.ErrorStage != "" {
		os.Exit(1)
	}
}
