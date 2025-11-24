package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"syscall"
)

type App struct {
	cfg             Config
	triggerDomain   string
	triggerIP       netip.Addr
	hops            []Hop
	aRecords        map[string]netip.Addr
	ptrRecords      map[string]string
	dnsTTL          uint32
	basePort        uint16
	portSpan        uint16
	logger          *slog.Logger
	packetIDCounter atomic.Uint32
}

type Hop struct {
	Name string
	IP   netip.Addr
}

func New(cfg Config) (*App, error) {
	triggerIP, err := netip.ParseAddr(cfg.TriggerIPv4)
	if err != nil {
		return nil, fmt.Errorf("parse trigger ip: %w", err)
	}
	if !triggerIP.Is4() {
		return nil, errors.New("trigger ip must be IPv4")
	}

	triggerDomain := canonicalFQDN(cfg.TriggerDomain)

	hops := make([]Hop, len(cfg.Lyrics))
	aRecords := map[string]netip.Addr{
		triggerDomain: triggerIP,
	}
	ptrRecords := make(map[string]string, len(cfg.Lyrics))

	for i, hopCfg := range cfg.Lyrics {
		ip, err := netip.ParseAddr(hopCfg.IPv4)
		if err != nil {
			return nil, fmt.Errorf("parse hop %s ip: %w", hopCfg.Name, err)
		}
		if !ip.Is4() {
			return nil, fmt.Errorf("hop %s is not IPv4", hopCfg.Name)
		}
		name := canonicalFQDN(hopCfg.Name)
		hops[i] = Hop{Name: name, IP: ip}
		aRecords[name] = ip
		ptrRecords[reverseIPv4(ip)] = name
	}

	if hops[len(hops)-1].IP != triggerIP {
		return nil, errors.New("last hop IPv4 must match trigger IPv4")
	}

	portSpan := cfg.TracerouteSpan
	minSpan := uint16(len(hops)) + 8
	if portSpan < minSpan {
		portSpan = minSpan
	}

	return &App{
		cfg:           cfg,
		triggerDomain: triggerDomain,
		triggerIP:     triggerIP,
		hops:          hops,
		aRecords:      aRecords,
		ptrRecords:    ptrRecords,
		dnsTTL:        cfg.DNSTTLSeconds,
		basePort:      cfg.TracerouteBase,
		portSpan:      portSpan,
		logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	}, nil
}

func (a *App) Run(ctx context.Context) error {
	client, err := openRawSocket(a.cfg.ClientInterface)
	if err != nil {
		return fmt.Errorf("attach to client interface: %w", err)
	}
	defer client.Close()

	upstream, err := openRawSocket(a.cfg.UpstreamInterface)
	if err != nil {
		return fmt.Errorf("attach to upstream interface: %w", err)
	}
	defer upstream.Close()

	errCh := make(chan error, 2)

	go func() {
		errCh <- a.pump(ctx, client, upstream, true)
	}()
	go func() {
		errCh <- a.pump(ctx, upstream, client, false)
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func (a *App) pump(ctx context.Context, src, dst *rawSocket, fromClient bool) error {
	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, _, err := syscall.Recvfrom(src.fd, buf, 0)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("recv from %s: %w", src.name, err)
		}
		if n <= 0 {
			continue
		}

		frame := buf[:n]
		if fromClient {
			handled, handleErr := a.handleClientFrame(frame, src)
			if handleErr != nil {
				return handleErr
			}
			if handled {
				continue
			}
		}

		if err := dst.send(frame); err != nil {
			return fmt.Errorf("forward %s -> %s: %w", src.name, dst.name, err)
		}
	}
}
