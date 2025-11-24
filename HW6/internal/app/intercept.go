package app

import (
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
)

func (a *App) handleClientFrame(frame []byte, iface *rawSocket) (bool, error) {
	eth, err := parseEthernet(frame)
	if err != nil {
		return false, nil
	}
	if eth.etherType != etherTypeIPv4 {
		return false, nil
	}

	ipPacket, err := parseIPv4(eth.payload)
	if err != nil {
		return false, nil
	}

	switch ipPacket.protocol {
	case ipProtoUDP:
		udpPacket, err := parseUDP(ipPacket.payload)
		if err != nil {
			return false, nil
		}

		if udpPacket.dstPort == dnsPort {
			handled, handleErr := a.interceptDNS(eth, ipPacket, udpPacket, iface)
			if handled || handleErr != nil {
				return handled, handleErr
			}
		}

		if ipPacket.dst == a.triggerIP && a.portInRange(udpPacket.dstPort) {
			handled, handleErr := a.interceptTraceroute(eth, ipPacket, iface)
			return handled, handleErr
		}
	}

	return false, nil
}

func (a *App) portInRange(port uint16) bool {
	max := uint32(a.basePort) + uint32(a.portSpan)
	return uint32(port) >= uint32(a.basePort) && uint32(port) < max
}

func (a *App) interceptDNS(eth *ethernetFrame, ipPacket *ipv4Packet, udpPacket *udpPacket, iface *rawSocket) (bool, error) {
	query, err := parseDNSQuery(udpPacket.payload)
	if err != nil {
		return false, nil
	}

	answer, err := a.dnsAnswerFor(query.question)
	if err != nil {
		return true, err
	}
	if answer == nil {
		return false, nil
	}

	payload, err := buildDNSResponse(query, answer)
	if err != nil {
		return true, err
	}

	frame, err := a.buildDNSFrame(eth, ipPacket, udpPacket, payload)
	if err != nil {
		return true, err
	}
	if err := iface.send(frame); err != nil {
		return true, err
	}

	a.logger.Info("answered DNS query",
		slog.String("name", query.question.Name),
		slog.Uint64("ttl", uint64(answer.ttl)),
		slog.Int("bytes", len(payload)))
	return true, nil
}

func (a *App) interceptTraceroute(eth *ethernetFrame, ipPacket *ipv4Packet, iface *rawSocket) (bool, error) {
	if len(a.hops) == 0 {
		return false, nil
	}

	ttl := int(ipPacket.ttl)
	if ttl < 1 {
		ttl = 1
	}

	targetIdx := ttl - 1
	if targetIdx >= len(a.hops) {
		targetIdx = len(a.hops) - 1
	}
	hop := a.hops[targetIdx]

	icmpType := uint8(11)
	code := uint8(0)
	reached := false

	if ttl-1 >= len(a.hops)-1 {
		icmpType = 3
		code = 3
		reached = true
	}

	frame, err := a.buildICMPFrame(eth, ipPacket, hop.IP, icmpType, code)
	if err != nil {
		return true, err
	}
	if err := iface.send(frame); err != nil {
		return true, err
	}

	if reached {
		a.logger.Info("delivered final hop",
			slog.String("hop", hop.Name),
			slog.String("client", ipPacket.src.String()))
	} else {
		a.logger.Info("spoofed hop",
			slog.String("hop", hop.Name),
			slog.Int("ttl", ttl))
	}
	return true, nil
}

func (a *App) buildDNSFrame(eth *ethernetFrame, ipPacket *ipv4Packet, udpPacket *udpPacket, payload []byte) ([]byte, error) {
	udpLen := 8 + len(payload)
	udpResp := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpResp[0:2], udpPacket.dstPort)
	binary.BigEndian.PutUint16(udpResp[2:4], udpPacket.srcPort)
	binary.BigEndian.PutUint16(udpResp[4:6], uint16(udpLen))
	copy(udpResp[8:], payload)
	binary.BigEndian.PutUint16(udpResp[6:8], 0)
	binary.BigEndian.PutUint16(udpResp[6:8], udpChecksum(ipPacket.dst, ipPacket.src, udpResp))

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	totalLen := 20 + len(udpResp)
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	packetID := uint16(a.packetIDCounter.Add(1))
	binary.BigEndian.PutUint16(ipHeader[4:6], packetID)
	ipHeader[8] = 64
	ipHeader[9] = ipProtoUDP
	writeIPv4(ipHeader[12:16], ipPacket.dst)
	writeIPv4(ipHeader[16:20], ipPacket.src)
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum(ipHeader))

	frame := make([]byte, ethernetHeaderLen+len(ipHeader)+len(udpResp))
	copy(frame[0:6], eth.src[:])
	copy(frame[6:12], eth.dst[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	copy(frame[14:14+len(ipHeader)], ipHeader)
	copy(frame[14+len(ipHeader):], udpResp)
	return frame, nil
}

func (a *App) buildICMPFrame(eth *ethernetFrame, ipPacket *ipv4Packet, srcIP netip.Addr, icmpType, icmpCode uint8) ([]byte, error) {
	if len(ipPacket.header) < 20 {
		return nil, fmt.Errorf("ipv4 header too short for icmp reflection")
	}

	originalHeader := make([]byte, len(ipPacket.header))
	copy(originalHeader, ipPacket.header)
	originalHeader[8] = 0
	binary.BigEndian.PutUint16(originalHeader[10:12], 0)
	binary.BigEndian.PutUint16(originalHeader[10:12], checksum(originalHeader))

	payloadBytes := min(len(ipPacket.payload), 8)
	icmpPayloadLen := 8 + len(originalHeader) + payloadBytes
	icmpPayload := make([]byte, icmpPayloadLen)
	icmpPayload[0] = icmpType
	icmpPayload[1] = icmpCode
	copy(icmpPayload[8:], originalHeader)
	copy(icmpPayload[8+len(originalHeader):], ipPacket.payload[:payloadBytes])
	binary.BigEndian.PutUint16(icmpPayload[2:4], 0)
	binary.BigEndian.PutUint16(icmpPayload[2:4], checksum(icmpPayload))

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45
	totalLen := 20 + len(icmpPayload)
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	packetID := uint16(a.packetIDCounter.Add(1))
	binary.BigEndian.PutUint16(ipHeader[4:6], packetID)
	ipHeader[8] = 64
	ipHeader[9] = ipProtoICMP
	writeIPv4(ipHeader[12:16], srcIP)
	writeIPv4(ipHeader[16:20], ipPacket.src)
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum(ipHeader))

	frame := make([]byte, ethernetHeaderLen+len(ipHeader)+len(icmpPayload))
	copy(frame[0:6], eth.src[:])
	copy(frame[6:12], eth.dst[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	copy(frame[14:14+len(ipHeader)], ipHeader)
	copy(frame[14+len(ipHeader):], icmpPayload)
	return frame, nil
}
