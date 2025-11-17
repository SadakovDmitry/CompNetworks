package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func runTLSServer(listenAddr, certFile, keyFile string) error {
	if listenAddr == "" {
		listenAddr = ":8443"
	}

	tlsConfig, err := newServerTLSConfig(certFile, keyFile)
	if err != nil {
		return err
	}

	ln, err := tls.Listen("tcp", listenAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start TLS listener on %s: %w", listenAddr, err)
	}
	defer ln.Close()

	log.Printf("TLS server listening on %s", listenAddr)
	log.Printf("Use SSLKEYLOGFILE environment variable to log session keys for Wireshark")

	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept error: %w", err)
		}

		go handleTLSConnection(conn)
	}
}

func handleTLSConnection(conn net.Conn) {
	defer conn.Close()
	log.Printf("New TLS client from %s", conn.RemoteAddr())

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Printf("read error from %s: %v", conn.RemoteAddr(), err)
			}
			return
		}
		log.Printf("Received from %s: %q", conn.RemoteAddr(), line)
		if _, err := conn.Write([]byte("echo: " + line)); err != nil {
			log.Printf("write error to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

func runTLSClient(addr, caFile, serverName string, insecure bool) error {
	if addr == "" {
		addr = "localhost:8443"
	}

	tlsConfig, err := newClientTLSConfig(caFile, serverName, insecure)
	if err != nil {
		return err
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to connect to TLS server %s: %w", addr, err)
	}
	defer conn.Close()

	log.Printf("Connected to TLS server %s", addr)
	log.Printf("Type text and press Enter to send. Type 'quit' to exit.")

	// Чтение из сервера → stdout.
	go func() {
		reader := bufio.NewReader(conn)
		for {
			resp, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Printf("error reading from server: %v", err)
				}
				return
			}
			fmt.Printf("[server] %s", resp)
		}
	}()

	// Чтение из stdin → сервер.
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := scanner.Text()
		if line == "quit" {
			break
		}
		if _, err := conn.Write([]byte(line + "\n")); err != nil {
			return fmt.Errorf("failed to send data to server: %w", err)
		}
	}

	return nil
}

func main() {
	mode := flag.String("mode", "", "Mode: server or client")
	listenAddr := flag.String("listen", ":8443", "Address for TLS server to listen on (server mode)")
	serverAddr := flag.String("addr", "localhost:8443", "TLS server address to connect to (client mode)")

	certFile := flag.String("cert", "", "Path to TLS certificate file (PEM, for server mode)")
	keyFile := flag.String("key", "", "Path to TLS private key file (PEM, for server mode)")

	caFile := flag.String("ca", "", "Path to CA certificate file to trust (PEM, for client mode)")
	serverName := flag.String("server-name", "", "Expected TLS server name (for certificate verification)")
	insecure := flag.Bool("insecure", true, "Skip certificate verification in TLS client (NOT secure, but useful for self-signed certs)")

	flag.Parse()

	if *certFile == "" {
		if v := os.Getenv("TLS_CERT_FILE"); v != "" {
			*certFile = v
		}
	}
	if *keyFile == "" {
		if v := os.Getenv("TLS_KEY_FILE"); v != "" {
			*keyFile = v
		}
	}

	switch *mode {
	case "server":
		if *certFile == "" || *keyFile == "" {
			fmt.Println("TLS server requires certificate and key.")
			fmt.Println("You can provide them via flags -cert/-key or env TLS_CERT_FILE/TLS_KEY_FILE.")
			os.Exit(1)
		}
		if err := runTLSServer(*listenAddr, *certFile, *keyFile); err != nil {
			log.Fatalf("TLS server error: %v", err)
		}
	case "client":
		if err := runTLSClient(*serverAddr, *caFile, *serverName, *insecure); err != nil {
			log.Fatalf("TLS client error: %v", err)
		}
	default:
		fmt.Println("Usage:")
		fmt.Println("  TLS server:")
		fmt.Println("    SSLKEYLOGFILE=keys.log go run . -mode=server -listen=:8443 -cert=server.crt -key=server.key")
		fmt.Println("  TLS client:")
		fmt.Println("    SSLKEYLOGFILE=keys.log go run . -mode=client -addr=localhost:8443 [-ca=ca.crt] [-server-name=example.com] [-insecure=true]")
		os.Exit(1)
	}
}


