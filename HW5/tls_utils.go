package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
)

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func newKeyLogWriter() (io.Writer, error) {
	path := os.Getenv("SSLKEYLOGFILE")
	if path == "" {
		return nil, nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open SSL key log file %q: %w", path, err)
	}

	log.Printf("TLS session keys will be logged to %s", path)
	return &lockedWriter{w: f}, nil
}

func newServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("both certFile and keyFile must be provided for TLS server")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate or key: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if w, err := newKeyLogWriter(); err != nil {
		return nil, err
	} else if w != nil {
		cfg.KeyLogWriter = w
	}

	return cfg, nil
}

func newClientTLSConfig(caFile, serverName string, insecure bool) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if serverName != "" {
		cfg.ServerName = serverName
	}

	if insecure {
		cfg.InsecureSkipVerify = true
	} else if caFile != "" {
		pemData, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file %q: %w", caFile, err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(pemData) {
			return nil, fmt.Errorf("no certificates could be parsed from CA file %q", caFile)
		}
		cfg.RootCAs = rootCAs
	}

	if w, err := newKeyLogWriter(); err != nil {
		return nil, err
	} else if w != nil {
		cfg.KeyLogWriter = w
	}

	return cfg, nil
}


