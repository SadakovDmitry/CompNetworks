package app

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

const (
	ethernetHeaderLen = 14
	etherTypeIPv4     = 0x0800

	ipProtoICMP = 1
	ipProtoUDP  = 17

	dnsPort = 53
)

type ethernetFrame struct {
	dst       [6]byte
	src       [6]byte
	etherType uint16
	payload   []byte
}

func parseEthernet(frame []byte) (*ethernetFrame, error) {
	if len(frame) < ethernetHeaderLen {
		return nil, errors.New("ethernet frame too short")
	}
	var res ethernetFrame
	copy(res.dst[:], frame[0:6])
	copy(res.src[:], frame[6:12])
	res.etherType = binary.BigEndian.Uint16(frame[12:14])
	res.payload = frame[ethernetHeaderLen:]
	return &res, nil
}

type ipv4Packet struct {
	headerLen int
	totalLen  int
	ttl       uint8
	protocol  uint8
	src       netip.Addr
	dst       netip.Addr
	payload   []byte
	header    []byte
}

func parseIPv4(data []byte) (*ipv4Packet, error) {
	if len(data) < 20 {
		return nil, errors.New("ipv4 header too short")
	}
	ihl := int(data[0]&0x0F) * 4
	if ihl < 20 || len(data) < ihl {
		return nil, errors.New("invalid ipv4 ihl")
	}
	totalLen := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLen < ihl || totalLen > len(data) {
		return nil, errors.New("invalid ipv4 total length")
	}

	header := make([]byte, ihl)
	copy(header, data[:ihl])

	src := netip.AddrFrom4([4]byte{data[12], data[13], data[14], data[15]})
	dst := netip.AddrFrom4([4]byte{data[16], data[17], data[18], data[19]})

	return &ipv4Packet{
		headerLen: ihl,
		totalLen:  totalLen,
		ttl:       data[8],
		protocol:  data[9],
		src:       src,
		dst:       dst,
		payload:   data[ihl:totalLen],
		header:    header,
	}, nil
}

type udpPacket struct {
	srcPort uint16
	dstPort uint16
	length  uint16
	payload []byte
}

func parseUDP(data []byte) (*udpPacket, error) {
	if len(data) < 8 {
		return nil, errors.New("udp header too short")
	}
	length := int(binary.BigEndian.Uint16(data[4:6]))
	if length < 8 || length > len(data) {
		return nil, errors.New("invalid udp length")
	}
	return &udpPacket{
		srcPort: binary.BigEndian.Uint16(data[0:2]),
		dstPort: binary.BigEndian.Uint16(data[2:4]),
		length:  uint16(length),
		payload: data[8:length],
	}, nil
}

func checksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func udpChecksum(src, dst netip.Addr, udp []byte) uint16 {
	pseudo := make([]byte, 12)
	srcBytes := src.As4()
	dstBytes := dst.As4()
	copy(pseudo[0:4], srcBytes[:])
	copy(pseudo[4:8], dstBytes[:])
	pseudo[9] = ipProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))

	sumBuf := append(pseudo, udp...)
	return checksum(sumBuf)
}

func canonicalFQDN(name string) string {
	name = strings.TrimSpace(name)
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return "."
	}
	return strings.ToLower(name) + "."
}

func reverseIPv4(addr netip.Addr) string {
	if !addr.Is4() {
		return "."
	}
	octets := addr.As4()
	return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", octets[3], octets[2], octets[1], octets[0])
}

func writeIPv4(dst []byte, addr netip.Addr) {
	b := addr.As4()
	copy(dst, b[:])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
