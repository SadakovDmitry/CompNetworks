package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)


type STUNServer struct {
	port     int
	conn     *net.UDPConn
	peers    map[string]*PeerInfo
	peerPairs map[string]string
}

type PeerInfo struct {
	ID          string
	LocalAddr   *net.UDPAddr
	ExternalAddr *net.UDPAddr
    ReportedLocalAddr *net.UDPAddr
	LastSeen    time.Time
}

func NewSTUNServer(port int) *STUNServer {
	return &STUNServer{
		port:      port,
		peers:     make(map[string]*PeerInfo),
		peerPairs: make(map[string]string),
	}
}

func (s *STUNServer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to resolve address: %v", err)
	}

	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}

	fmt.Printf("STUN/Rendezvous Server listening on port %d\n", s.port)
	fmt.Println("Server will help clients discover their external addresses and connect peers")

	buffer := make([]byte, 1024)


	go s.cleanupPeers()

	for {
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}

		if n < 1 {
			continue
		}

		msgType := buffer[0]
		payload := buffer[1:n]

		switch msgType {
		case STUN_REQUEST:
			s.handleSTUNRequest(clientAddr)
		case PEER_INFO_REQ:
			s.handlePeerInfoRequest(clientAddr, payload)
		case PEER_READY:
			s.handlePeerReady(clientAddr, payload)
		case PEER_CONNECT:
			s.handlePeerConnect(clientAddr, payload)
		default:
			log.Printf("Unknown message type: %d from %s", msgType, clientAddr)
		}
	}
}


func (s *STUNServer) handleSTUNRequest(clientAddr *net.UDPAddr) {


	response := make([]byte, 1+4+2)
	response[0] = STUN_RESPONSE


	ip := clientAddr.IP.To4()
	if ip == nil {

		ip = clientAddr.IP.To16()[:4]
	}
	copy(response[1:5], ip)
	binary.BigEndian.PutUint16(response[5:7], uint16(clientAddr.Port))

	_, err := s.conn.WriteToUDP(response, clientAddr)
	if err != nil {
		log.Printf("Error sending STUN response: %v", err)
	}

	fmt.Printf("STUN response sent to %s (external: %s:%d)\n",
		clientAddr, clientAddr.IP, clientAddr.Port)
}


func (s *STUNServer) handlePeerInfoRequest(clientAddr *net.UDPAddr, payload []byte) {

	parts := splitNullTerminated(payload)
	if len(parts) < 2 {
		log.Printf("Invalid peer info request from %s", clientAddr)
		return
	}

	peerID := string(parts[0])
	targetPeerID := string(parts[1])


	peerInfo := &PeerInfo{
		ID:          peerID,
		LocalAddr:   clientAddr,
		ExternalAddr: nil,
		LastSeen:    time.Now(),
	}
	s.peers[peerID] = peerInfo
	s.peerPairs[peerID] = targetPeerID

	fmt.Printf("Peer %s registered from %s, looking for peer %s\n",
		peerID, clientAddr, targetPeerID)


	targetPeer, exists := s.peers[targetPeerID]
	if exists {


		if targetPeer.ExternalAddr != nil {
			s.sendPeerInfo(peerID, targetPeer)
		} else {

			s.sendPeerInfoLocal(peerID, targetPeer)
		}
	}
}


func (s *STUNServer) handlePeerReady(clientAddr *net.UDPAddr, payload []byte) {

    if len(payload) < 7 {
		log.Printf("Invalid peer ready message from %s", clientAddr)
		return
	}


	nullIdx := -1
	for i, b := range payload {
		if b == 0 {
			nullIdx = i
			break
		}
	}
    if nullIdx == -1 || nullIdx+6 > len(payload) {
		log.Printf("Invalid peer ready message format from %s", clientAddr)
		return
	}

    peerID := string(payload[:nullIdx])

    extBytes := make([]byte, 4)
    copy(extBytes, payload[nullIdx+1:nullIdx+5])
    externalIP := net.IP(extBytes)
    externalPort := binary.BigEndian.Uint16(payload[nullIdx+5 : nullIdx+7])

    var reportedLocal *net.UDPAddr

    if nullIdx+12 <= len(payload) {
        locBytes := make([]byte, 4)
        copy(locBytes, payload[nullIdx+7:nullIdx+11])
        locIP := net.IP(locBytes)
        locPort := binary.BigEndian.Uint16(payload[nullIdx+11 : nullIdx+13])
        reportedLocal = &net.UDPAddr{IP: locIP, Port: int(locPort)}
    }

	peerInfo, exists := s.peers[peerID]
	if !exists {
		log.Printf("Unknown peer %s", peerID)
		return
	}


    externalAddr := &net.UDPAddr{IP: append(net.IP(nil), externalIP...), Port: int(externalPort)}
    peerInfo.ExternalAddr = externalAddr
    if reportedLocal != nil {
        peerInfo.ReportedLocalAddr = reportedLocal
    }
	peerInfo.LastSeen = time.Now()

	fmt.Printf("Peer %s ready with external address %s:%d\n",
		peerID, externalIP, externalPort)


	targetPeerID := s.peerPairs[peerID]
	if targetPeerID != "" {
		targetPeer, exists := s.peers[targetPeerID]
		if exists {

            if targetPeer.ExternalAddr != nil && peerInfo.ExternalAddr != nil {
				s.sendPeerInfo(peerID, targetPeer)
				s.sendPeerInfo(targetPeerID, peerInfo)
            } else if targetPeer.ExternalAddr != nil {

				s.sendPeerInfo(peerID, targetPeer)
				s.sendPeerInfoLocal(targetPeerID, peerInfo)
            } else if peerInfo.ExternalAddr != nil {

				s.sendPeerInfoLocal(peerID, targetPeer)
				s.sendPeerInfo(targetPeerID, peerInfo)
			} else {

				s.sendPeerInfoLocal(peerID, targetPeer)
				s.sendPeerInfoLocal(targetPeerID, peerInfo)
			}
		}
	}
}


func splitNullTerminated(data []byte) [][]byte {
	var result [][]byte
	start := 0
	for i, b := range data {
		if b == 0 {
			result = append(result, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		result = append(result, data[start:])
	}
	return result
}


func (s *STUNServer) sendPeerInfo(peerID string, targetPeer *PeerInfo) {
	peerInfo, exists := s.peers[peerID]
	if !exists {
		return
	}


    response := make([]byte, 1+4+2+4+2)
	response[0] = PEER_INFO


    extIP := targetPeer.ExternalAddr.IP.To4()
    if extIP == nil { extIP = targetPeer.ExternalAddr.IP.To16() }
    copy(response[1:], extIP[:4])
    binary.BigEndian.PutUint16(response[5:], uint16(targetPeer.ExternalAddr.Port))

    locIP := net.IPv4zero.To4()
    locPort := 0
    if targetPeer.ReportedLocalAddr != nil {
        if v := targetPeer.ReportedLocalAddr.IP.To4(); v != nil { locIP = v }
        locPort = targetPeer.ReportedLocalAddr.Port
    }
    copy(response[7:], locIP[:4])
    binary.BigEndian.PutUint16(response[11:], uint16(locPort))

	_, err := s.conn.WriteToUDP(response, peerInfo.LocalAddr)
	if err != nil {
		log.Printf("Error sending peer info: %v", err)
	} else {
        fmt.Printf("Sent peer info to %s: ext %s:%d, loc %s:%d\n",
            peerID,
            net.IP(response[1:5]), binary.BigEndian.Uint16(response[5:7]),
            net.IP(response[7:11]), binary.BigEndian.Uint16(response[11:13]))
	}
}


func (s *STUNServer) sendPeerInfoLocal(peerID string, targetPeer *PeerInfo) {
	peerInfo, exists := s.peers[peerID]
	if !exists {
		return
	}


    response := make([]byte, 1+4+2+4+2)
	response[0] = PEER_INFO


    extIP := targetPeer.LocalAddr.IP.To4()
    if extIP == nil { extIP = targetPeer.LocalAddr.IP.To16() }
    copy(response[1:], extIP[:4])
    binary.BigEndian.PutUint16(response[5:], uint16(targetPeer.LocalAddr.Port))

    locIP := net.IPv4zero.To4()
    locPort := 0
    if targetPeer.ReportedLocalAddr != nil {
        if v := targetPeer.ReportedLocalAddr.IP.To4(); v != nil { locIP = v }
        locPort = targetPeer.ReportedLocalAddr.Port
    }
    copy(response[7:], locIP[:4])
    binary.BigEndian.PutUint16(response[11:], uint16(locPort))

	_, err := s.conn.WriteToUDP(response, peerInfo.LocalAddr)
	if err != nil {
		log.Printf("Error sending peer info: %v", err)
	} else {
        fmt.Printf("Sent peer info (local) to %s: ext %s:%d, loc %s:%d\n",
            peerID,
            net.IP(response[1:5]), binary.BigEndian.Uint16(response[5:7]),
            net.IP(response[7:11]), binary.BigEndian.Uint16(response[11:13]))
	}
}


func (s *STUNServer) handlePeerConnect(clientAddr *net.UDPAddr, payload []byte) {
	fmt.Printf("Peer connection message from %s\n", clientAddr)
}


func (s *STUNServer) cleanupPeers() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		for id, peer := range s.peers {
			if now.Sub(peer.LastSeen) > 60*time.Second {
				delete(s.peers, id)
				delete(s.peerPairs, id)
				fmt.Printf("Removed inactive peer %s\n", id)
			}
		}
	}
}

func (s *STUNServer) Stop() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

