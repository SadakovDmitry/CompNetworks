package app

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	ethPAll = 0x0003

	solPacket            = 263
	packetAddMembership  = 1
	packetMrPromisc      = 1
	packetIgnoreOutgoing = 23
)

func openRawSocket(name string) (*rawSocket, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup interface %s: %w", name, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return nil, fmt.Errorf("create raw socket: %w", err)
	}

	syscall.CloseOnExec(fd)

	hlen := len(iface.HardwareAddr)
	if hlen == 0 {
		hlen = 6
	}
	bindAddr := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
		Halen:    uint8(hlen),
	}
	if err := syscall.Bind(fd, bindAddr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind to interface %s: %w", name, err)
	}

	if err := syscall.SetsockoptInt(fd, solPacket, packetIgnoreOutgoing, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("toggle PACKET_IGNORE_OUTGOING: %w", err)
	}

	if err := joinPromiscuous(fd, iface.Index); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("enter promiscuous mode on %s: %w", name, err)
	}

	sendAddr := &syscall.SockaddrLinklayer{
		Protocol: htons(ethPAll),
		Ifindex:  iface.Index,
		Halen:    uint8(hlen),
	}

	return &rawSocket{
		fd:       fd,
		name:     name,
		ifindex:  iface.Index,
		sendAddr: sendAddr,
	}, nil
}

func (r *rawSocket) Close() error {
	return syscall.Close(r.fd)
}

func (r *rawSocket) send(frame []byte) error {
	return syscall.Sendto(r.fd, frame, 0, r.sendAddr)
}

func joinPromiscuous(fd, ifindex int) error {
	mreq := packetMreq{
		Ifindex: int32(ifindex),
		Type:    packetMrPromisc,
	}
	return setsockoptPacketMreq(fd, solPacket, packetAddMembership, &mreq)
}

type packetMreq struct {
	Ifindex int32
	Type    uint16
	Alen    uint16
	Address [8]uint8
}

func setsockoptPacketMreq(fd, level, opt int, mreq *packetMreq) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(level),
		uintptr(opt),
		uintptr(unsafe.Pointer(mreq)),
		uintptr(unsafe.Sizeof(*mreq)),
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}

func htons(v uint16) uint16 {
	return (v<<8)&0xFF00 | v>>8
}
