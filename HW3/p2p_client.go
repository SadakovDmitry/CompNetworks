package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)




type P2PClient struct {
	stunServerAddr *net.UDPAddr
	peerID         string
	targetPeerID   string
	localConn      *net.UDPConn
	externalAddr   *net.UDPAddr
	peerAddr       *net.UDPAddr
    peerLocalAddr  *net.UDPAddr
	connected      bool
}

func NewP2PClient(stunServer string, peerID string, targetPeerID string) (*P2PClient, error) {
	addr, err := net.ResolveUDPAddr("udp", stunServer)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server address: %v", err)
	}

	
	localConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %v", err)
	}

	fmt.Printf("Local UDP address: %s\n", localConn.LocalAddr())

	return &P2PClient{
		stunServerAddr: addr,
		peerID:         peerID,
		targetPeerID:   targetPeerID,
		localConn:      localConn,
		connected:      false,
	}, nil
}


func (c *P2PClient) discoverExternalAddress() error {
	fmt.Println("Step 1: Discovering external address via STUN...")

	
	request := []byte{STUN_REQUEST}
	_, err := c.localConn.WriteToUDP(request, c.stunServerAddr)
	if err != nil {
		return fmt.Errorf("failed to send STUN request: %v", err)
	}

	
	buffer := make([]byte, 1024)
	c.localConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := c.localConn.ReadFromUDP(buffer)
	if err != nil {
		return fmt.Errorf("failed to receive STUN response: %v", err)
	}

	if n < 7 || buffer[0] != STUN_RESPONSE {
		return fmt.Errorf("invalid STUN response")
	}

	
	externalIP := net.IP(buffer[1:5])
	externalPort := binary.BigEndian.Uint16(buffer[5:7])

	c.externalAddr = &net.UDPAddr{
		IP:   externalIP,
		Port: int(externalPort),
	}

	fmt.Printf("External address discovered: %s:%d\n", externalIP, externalPort)
	return nil
}


func (c *P2PClient) registerWithRendezvous() error {
	fmt.Println("Step 2: Registering with rendezvous server...")

	
	message := make([]byte, 0, len(c.peerID)+len(c.targetPeerID)+2)
	message = append(message, PEER_INFO_REQ)
	message = append(message, []byte(c.peerID)...)
	message = append(message, 0)
	message = append(message, []byte(c.targetPeerID)...)

	_, err := c.localConn.WriteToUDP(message, c.stunServerAddr)
	if err != nil {
		return fmt.Errorf("failed to register: %v", err)
	}

	fmt.Printf("Registered as peer %s, looking for peer %s\n", c.peerID, c.targetPeerID)
	return nil
}


func (c *P2PClient) sendReady() error {
	fmt.Println("Step 3: Sending ready status...")

    
    localPort := uint16(c.localConn.LocalAddr().(*net.UDPAddr).Port)
    localIP := detectLocalIPv4()

    
    message := make([]byte, 0, 1+len(c.peerID)+1+4+2+4+2)
	message = append(message, PEER_READY)
	message = append(message, []byte(c.peerID)...)
	message = append(message, 0)
	message = append(message, c.externalAddr.IP.To4()...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(c.externalAddr.Port))
	message = append(message, portBytes...)
    
    if localIP != nil {
        message = append(message, localIP.To4()...)
    } else {
        message = append(message, []byte{0, 0, 0, 0}...)
    }
    lb := make([]byte, 2)
    binary.BigEndian.PutUint16(lb, localPort)
    message = append(message, lb...)

	_, err := c.localConn.WriteToUDP(message, c.stunServerAddr)
	if err != nil {
		return fmt.Errorf("failed to send ready: %v", err)
	}

	fmt.Println("Ready status sent")
	return nil
}


func (c *P2PClient) waitForPeerInfo() error {
	fmt.Println("Step 4: Waiting for peer info from rendezvous server...")

	for {
		buffer := make([]byte, 1024)
		c.localConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, _, err := c.localConn.ReadFromUDP(buffer)
		if err != nil {
			return fmt.Errorf("failed to receive peer info: %v", err)
		}

        if n >= 7 && buffer[0] == PEER_INFO {
            
            peerIP := net.IP(buffer[1:5])
            peerPort := binary.BigEndian.Uint16(buffer[5:7])
            c.peerAddr = &net.UDPAddr{IP: peerIP, Port: int(peerPort)}

            if n >= 13 {
                locIP := net.IP(buffer[7:11])
                locPort := binary.BigEndian.Uint16(buffer[11:13])
                if !locIP.Equal(net.IPv4zero) && locPort != 0 {
                    c.peerLocalAddr = &net.UDPAddr{IP: locIP, Port: int(locPort)}
                }
            }

            if c.peerLocalAddr != nil {
                fmt.Printf("Peer info received: ext %s:%d, loc %s:%d\n",
                    peerIP, peerPort, c.peerLocalAddr.IP, c.peerLocalAddr.Port)
            } else {
                fmt.Printf("Peer info received: ext %s:%d\n", peerIP, peerPort)
            }
            return nil
        }
	}
}


func (c *P2PClient) performHolePunching() error {
	fmt.Println("Step 5: Performing NAT hole punching...")
    if c.peerLocalAddr != nil {
        fmt.Printf("Attempting to connect to peer: ext %s:%d, loc %s:%d\n",
            c.peerAddr.IP, c.peerAddr.Port, c.peerLocalAddr.IP, c.peerLocalAddr.Port)
    } else {
        fmt.Printf("Attempting to connect to peer at %s:%d\n", c.peerAddr.IP, c.peerAddr.Port)
    }

	
	
	
	
	

	fmt.Println("Starting simultaneous send/receive for hole punching...")

	
	done := make(chan bool)
	connected := make(chan bool)

    go func() {
		
		for i := 0; i < 30; i++ {
			message := []byte{P2P_MESSAGE}
			message = append(message, []byte(fmt.Sprintf("Hole punch %d from %s", i, c.peerID))...)

            
            candidates := []*net.UDPAddr{c.peerAddr}
            if c.peerLocalAddr != nil {
                candidates = append(candidates, c.peerLocalAddr)
            }
            for _, cand := range candidates {
                _, err := c.localConn.WriteToUDP(message, cand)
                if err != nil {
                    log.Printf("Failed to send hole punch packet %d to %s:%d: %v", i, cand.IP, cand.Port, err)
                } else if i < 5 || i%5 == 0 {
                    fmt.Printf("→ Sent hole punch %d to %s:%d\n", i, cand.IP, cand.Port)
                }
            }

			
			if i < 10 {
				time.Sleep(50 * time.Millisecond)
			} else {
				time.Sleep(200 * time.Millisecond)
			}

			
			select {
			case <-connected:
				done <- true
				return
			default:
			}
		}
		done <- true
	}()

	
	
	startTime := time.Now()
	timeout := 15 * time.Second

	for {
		
		remaining := timeout - time.Since(startTime)
		if remaining <= 0 {
			if c.connected {
				return nil
			}
			return fmt.Errorf("timeout waiting for peer response")
		}
		c.localConn.SetReadDeadline(time.Now().Add(remaining))

		select {
		case <-connected:
			fmt.Println("✓ Connection established!")
			return nil
		case <-done:
			
			c.localConn.SetReadDeadline(time.Now().Add(3 * time.Second))
		default:
		}

		buffer := make([]byte, 1024)
		n, addr, err := c.localConn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				
				select {
				case <-connected:
					return nil
				default:
				}
				
				continue
			}
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		
		if n > 0 && buffer[0] == P2P_MESSAGE {
			
			
			isFromPeer := false
			if c.peerAddr != nil {
				
				isFromPeer = addr.IP.Equal(c.peerAddr.IP)
			} else {
				
				isFromPeer = true
			}

			if isFromPeer {
				fmt.Printf("✓ Received from peer %s:%d: %s\n", addr.IP, addr.Port, string(buffer[1:n]))

				
				if c.peerAddr == nil || !addr.IP.Equal(c.peerAddr.IP) || addr.Port != c.peerAddr.Port {
					if c.peerAddr != nil {
						fmt.Printf("  (Peer address updated: %s:%d → %s:%d)\n",
							c.peerAddr.IP, c.peerAddr.Port, addr.IP, addr.Port)
					}
					c.peerAddr = addr
				}

				c.connected = true
				connected <- true
				return nil
			}
		}
	}
}


func (c *P2PClient) startP2PCommunication() error {
	fmt.Println("\n=== P2P Connection Established! ===")
	fmt.Println("You can now send messages to your peer.")
	fmt.Println("Type 'quit' to exit.\n")

	
	go func() {
		for {
			buffer := make([]byte, 1024)
			c.localConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := c.localConn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Error reading from peer: %v", err)
				continue
			}

			
			
			if n > 0 && buffer[0] == P2P_MESSAGE {
				if c.peerAddr != nil && addr.IP.Equal(c.peerAddr.IP) {
					
					if addr.Port != c.peerAddr.Port {
						c.peerAddr = addr
					}
					fmt.Printf("\n[Peer %s]: %s\n> ", addr, string(buffer[1:n]))
				} else if c.peerAddr == nil {
					
					c.peerAddr = addr
					fmt.Printf("\n[Peer %s]: %s\n> ", addr, string(buffer[1:n]))
				}
			}
		}
	}()

	
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		message := scanner.Text()
		if message == "quit" {
			break
		}

		
		p2pMessage := []byte{P2P_MESSAGE}
		p2pMessage = append(p2pMessage, []byte(message)...)

		_, err := c.localConn.WriteToUDP(p2pMessage, c.peerAddr)
		if err != nil {
			log.Printf("Failed to send message: %v", err)
		}
	}

	return nil
}


func (c *P2PClient) Connect() error {
	
	if err := c.discoverExternalAddress(); err != nil {
		return fmt.Errorf("discovery failed: %v", err)
	}

	
	if err := c.registerWithRendezvous(); err != nil {
		return fmt.Errorf("registration failed: %v", err)
	}

	
	if err := c.sendReady(); err != nil {
		return fmt.Errorf("ready failed: %v", err)
	}

	
	if err := c.waitForPeerInfo(); err != nil {
		return fmt.Errorf("peer info failed: %v", err)
	}

	
	if err := c.performHolePunching(); err != nil {
		return fmt.Errorf("hole punching failed: %v", err)
	}

	
	return c.startP2PCommunication()
}

func (c *P2PClient) Close() error {
	if c.localConn != nil {
		return c.localConn.Close()
	}
	return nil
}


func detectLocalIPv4() net.IP {
    ifaces, err := net.Interfaces()
    if err != nil {
        return nil
    }
    for _, iface := range ifaces {
        if (iface.Flags & net.FlagUp) == 0 { continue }
        if (iface.Flags & net.FlagLoopback) != 0 { continue }
        addrs, err := iface.Addrs()
        if err != nil { continue }
        for _, a := range addrs {
            var ip net.IP
            switch v := a.(type) {
            case *net.IPNet:
                ip = v.IP
            case *net.IPAddr:
                ip = v.IP
            }
            if ip == nil { continue }
            ip4 := ip.To4()
            if ip4 == nil { continue }
            if !ip4.IsLoopback() {
                return ip4
            }
        }
    }
    return nil
}

func main() {
	var (
		mode        = flag.String("mode", "", "Mode: server or client")
		stunServer  = flag.String("stun", "localhost:3478", "STUN/Rendezvous server address")
		port        = flag.Int("port", 3478, "Port (for server mode)")
		peerID      = flag.String("peer", "", "Your peer ID (for client mode)")
		targetPeer  = flag.String("target", "", "Target peer ID (for client mode)")
	)
	flag.Parse()

	if *mode == "server" {
		
		server := NewSTUNServer(*port)
		if err := server.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	} else if *mode == "client" {
		if *peerID == "" || *targetPeer == "" {
			fmt.Println("Usage for client mode:")
			fmt.Println("  go run *.go -mode=client -stun=server:port -peer=peer1 -target=peer2")
			os.Exit(1)
		}

		client, err := NewP2PClient(*stunServer, *peerID, *targetPeer)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()

		if err := client.Connect(); err != nil {
			log.Fatalf("Connection failed: %v", err)
		}
	} else {
		fmt.Println("Usage:")
		fmt.Println("  Server mode:")
		fmt.Println("    go run *.go -mode=server -port=3478")
		fmt.Println("  Client mode:")
		fmt.Println("    go run *.go -mode=client -stun=server:port -peer=peer1 -target=peer2")
		fmt.Println("\nExample:")
		fmt.Println("  Terminal 1: go run *.go -mode=server -port=3478")
		fmt.Println("  Terminal 2: go run *.go -mode=client -stun=localhost:3478 -peer=alice -target=bob")
		fmt.Println("  Terminal 3: go run *.go -mode=client -stun=localhost:3478 -peer=bob -target=alice")
		os.Exit(1)
	}
}

