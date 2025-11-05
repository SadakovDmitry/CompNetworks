package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

// STUN сообщения используют простой формат
// Для упрощения используем простой протокол:
// Тип сообщения (1 байт) + данные
// Константы протокола определены в protocol.go

// STUN сервер для определения внешнего IP и порта
type STUNServer struct {
	port     int
	conn     *net.UDPConn
	peers    map[string]*PeerInfo
	peerPairs map[string]string // Связь между peer ID
}

type PeerInfo struct {
	ID          string
	LocalAddr   *net.UDPAddr  // Локальный адрес (как видит сервер)
	ExternalAddr *net.UDPAddr // Внешний адрес (который клиент узнал через STUN)
    ReportedLocalAddr *net.UDPAddr // Локальный адрес, который сообщил клиент (внутрисетевой)
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

	// Очистка старых пиров каждые 30 секунд
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

// Обработка STUN запроса - возвращаем клиенту его внешний адрес
func (s *STUNServer) handleSTUNRequest(clientAddr *net.UDPAddr) {
	// Отправляем обратно адрес клиента как его внешний адрес
	// Формат: тип (1 байт) + IP (4 байта для IPv4) + Port (2 байта)
	response := make([]byte, 1+4+2)
	response[0] = STUN_RESPONSE

	// Кодируем IP и порт
	ip := clientAddr.IP.To4()
	if ip == nil {
		// Если IPv6, используем первые 4 байта для упрощения
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

// Обработка запроса информации о пире
func (s *STUNServer) handlePeerInfoRequest(clientAddr *net.UDPAddr, payload []byte) {
	// Формат: peerID + '\0' + targetPeerID
	parts := splitNullTerminated(payload)
	if len(parts) < 2 {
		log.Printf("Invalid peer info request from %s", clientAddr)
		return
	}

	peerID := string(parts[0])
	targetPeerID := string(parts[1])

	// Сохраняем информацию о пире
	peerInfo := &PeerInfo{
		ID:          peerID,
		LocalAddr:   clientAddr,
		ExternalAddr: nil, // Будет установлен позже
		LastSeen:    time.Now(),
	}
	s.peers[peerID] = peerInfo
	s.peerPairs[peerID] = targetPeerID

	fmt.Printf("Peer %s registered from %s, looking for peer %s\n",
		peerID, clientAddr, targetPeerID)

	// Проверяем, есть ли уже целевой пир и можно ли обменяться информацией
	targetPeer, exists := s.peers[targetPeerID]
	if exists {
		// Если целевой пир уже зарегистрирован, отправляем информацию
		// даже если ExternalAddr еще не установлен (для случая одной сети)
		if targetPeer.ExternalAddr != nil {
			s.sendPeerInfo(peerID, targetPeer)
		} else {
			// Отправляем локальный адрес для случая одной сети
			s.sendPeerInfoLocal(peerID, targetPeer)
		}
	}
}

// Обработка готовности пира (когда он узнал свой внешний адрес)
func (s *STUNServer) handlePeerReady(clientAddr *net.UDPAddr, payload []byte) {
    // Формат: peerID + '\0' + ExtIP(4) + ExtPort(2) [+ LocIP(4) + LocPort(2)]
    if len(payload) < 7 {
		log.Printf("Invalid peer ready message from %s", clientAddr)
		return
	}

	// Находим нулевой байт, разделяющий peerID и данные адреса
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
    // ВАЖНО: скопировать байты IP, чтобы не держать слайс на общий буфер
    extBytes := make([]byte, 4)
    copy(extBytes, payload[nullIdx+1:nullIdx+5])
    externalIP := net.IP(extBytes)
    externalPort := binary.BigEndian.Uint16(payload[nullIdx+5 : nullIdx+7])

    var reportedLocal *net.UDPAddr
    // Дополнительно можем получить локальный адрес клиента, если он прислан
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

    // Сохраняем копию адреса, чтобы не зависеть от переиспользуемого буфера
    externalAddr := &net.UDPAddr{IP: append(net.IP(nil), externalIP...), Port: int(externalPort)}
    peerInfo.ExternalAddr = externalAddr
    if reportedLocal != nil {
        peerInfo.ReportedLocalAddr = reportedLocal
    }
	peerInfo.LastSeen = time.Now()

	fmt.Printf("Peer %s ready with external address %s:%d\n",
		peerID, externalIP, externalPort)

	// Если есть пара, отправляем информацию друг другу
	targetPeerID := s.peerPairs[peerID]
	if targetPeerID != "" {
		targetPeer, exists := s.peers[targetPeerID]
		if exists {
			// Если оба пира имеют внешние адреса, отправляем их
            if targetPeer.ExternalAddr != nil && peerInfo.ExternalAddr != nil {
				s.sendPeerInfo(peerID, targetPeer)
				s.sendPeerInfo(targetPeerID, peerInfo)
            } else if targetPeer.ExternalAddr != nil {
				// Только целевой пир имеет внешний адрес
				s.sendPeerInfo(peerID, targetPeer)
				s.sendPeerInfoLocal(targetPeerID, peerInfo)
            } else if peerInfo.ExternalAddr != nil {
				// Только текущий пир имеет внешний адрес
				s.sendPeerInfoLocal(peerID, targetPeer)
				s.sendPeerInfo(targetPeerID, peerInfo)
			} else {
				// Оба пира в одной сети - используем локальные адреса
				s.sendPeerInfoLocal(peerID, targetPeer)
				s.sendPeerInfoLocal(targetPeerID, peerInfo)
			}
		}
	}
}

// Вспомогательная функция для разделения по нулевому байту
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

// Отправка информации о пире (с внешним адресом)
func (s *STUNServer) sendPeerInfo(peerID string, targetPeer *PeerInfo) {
	peerInfo, exists := s.peers[peerID]
	if !exists {
		return
	}

    // Формат: тип (1) + ExtIP(4)+ExtPort(2) + LocIP(4)+LocPort(2)
    response := make([]byte, 1+4+2+4+2)
	response[0] = PEER_INFO

    // External candidate
    extIP := targetPeer.ExternalAddr.IP.To4()
    if extIP == nil { extIP = targetPeer.ExternalAddr.IP.To16() }
    copy(response[1:], extIP[:4])
    binary.BigEndian.PutUint16(response[5:], uint16(targetPeer.ExternalAddr.Port))
    // Local candidate (reported by peer, fallback to zeroes if absent)
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

// Отправка информации о пире (с локальным адресом для случая одной сети)
func (s *STUNServer) sendPeerInfoLocal(peerID string, targetPeer *PeerInfo) {
	peerInfo, exists := s.peers[peerID]
	if !exists {
		return
	}

    // Формат: тип (1) + ExtIP(4)+ExtPort(2) + LocIP(4)+LocPort(2)
    response := make([]byte, 1+4+2+4+2)
	response[0] = PEER_INFO

    // В этом варианте ext-кандидатом считаем адрес, который видит сервер (может быть внешний)
    extIP := targetPeer.LocalAddr.IP.To4()
    if extIP == nil { extIP = targetPeer.LocalAddr.IP.To16() }
    copy(response[1:], extIP[:4])
    binary.BigEndian.PutUint16(response[5:], uint16(targetPeer.LocalAddr.Port))
    // Local candidate — предпочитаем ReportedLocalAddr, иначе нули
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

// Обработка сообщения о подключении (для логирования)
func (s *STUNServer) handlePeerConnect(clientAddr *net.UDPAddr, payload []byte) {
	fmt.Printf("Peer connection message from %s\n", clientAddr)
}

// Очистка неактивных пиров
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

