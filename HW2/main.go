package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	BUFFER_SIZE = 1024
	LARGE_MESSAGE_SIZE = 20480 // 20KB для тестирования больших сообщений
)

type Server interface {
	Start() error
	Stop() error
}

type Client interface {
	Connect() error
	SendMessage(message string) error
	ReceiveMessage() (string, error)
	Close() error
}

// TCP Server implementation
type TCPServer struct {
	port     int
	listener net.Listener
	conn     net.Conn
    wireMode string // "auto" | "framed" | "line"
}

func NewTCPServer(port int, wireMode string) *TCPServer {
    return &TCPServer{port: port, wireMode: wireMode}
}

func (s *TCPServer) Start() error {
	var err error
	s.listener, err = net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to start TCP server: %v", err)
	}

	fmt.Printf("TCP Server listening on port %d\n", s.port)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		fmt.Printf("New TCP connection from %s\n", conn.RemoteAddr())
		s.conn = conn

		// Handle client in current goroutine (as per requirements)
		s.handleClient(conn)
	}
}

func (s *TCPServer) handleClient(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

    lineMode := s.wireMode == "line"
    for {
        // Read first line
        line, err := reader.ReadString('\n')
        if err != nil {
            if err != io.EOF {
                log.Printf("Error reading from TCP: %v", err)
            }
            break
        }
        trimmed := strings.TrimSpace(line)

        if !lineMode && s.wireMode != "line" {
            // framed mode or auto-detect
            if length, err := strconv.Atoi(trimmed); err == nil {
                // Framed: read exact length bytes as message
                message := make([]byte, length)
                _, err = io.ReadFull(reader, message)
                if err != nil {
                    log.Printf("Error reading message: %v", err)
                    break
                }
                fmt.Printf("Received (%d bytes): %s\n", length, string(message))
                response := fmt.Sprintf("Echo: %s", string(message))
                // reply framed unless the client is in line mode
                if s.wireMode == "framed" {
                    _, err = writer.WriteString(fmt.Sprintf("%d\n", len(response)))
                    if err != nil { log.Printf("Error writing response length: %v", err); break }
                    _, err = writer.WriteString(response)
                    if err != nil { log.Printf("Error writing response: %v", err); break }
                    if err = writer.Flush(); err != nil { log.Printf("Error flushing response: %v", err); break }
                } else {
                    // auto mode: respond framed to framed input
                    _, err = writer.WriteString(fmt.Sprintf("%d\n", len(response)))
                    if err != nil { log.Printf("Error writing response length: %v", err); break }
                    _, err = writer.WriteString(response)
                    if err != nil { log.Printf("Error writing response: %v", err); break }
                    if err = writer.Flush(); err != nil { log.Printf("Error flushing response: %v", err); break }
                }
                continue
            }
            // Not a number: if auto, switch to line mode for compatibility (e.g., netcat)
            if s.wireMode == "auto" {
                lineMode = true
            } else if s.wireMode == "framed" {
                log.Printf("Invalid message length: %v", trimmed)
                continue
            }
        }

        // line mode: treat 'line' (without trailing \n) as the message
        message := trimmed
        fmt.Printf("Received (line): %s\n", message)
        response := fmt.Sprintf("Echo: %s", message)
        _, err = writer.WriteString(response + "\n")
        if err != nil { log.Printf("Error writing response: %v", err); break }
        if err = writer.Flush(); err != nil { log.Printf("Error flushing response: %v", err); break }
    }

	fmt.Println("TCP client disconnected")
}

func (s *TCPServer) Stop() error {
	if s.conn != nil {
		s.conn.Close()
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// TCP Client implementation
type TCPClient struct {
	host string
	port int
	conn net.Conn
    wireMode string // "auto" | "framed" | "line"
}

func NewTCPClient(host string, port int, wireMode string) *TCPClient {
    return &TCPClient{host: host, port: port, wireMode: wireMode}
}

func (c *TCPClient) Connect() error {
	var err error
	c.conn, err = net.Dial("tcp", fmt.Sprintf("%s:%d", c.host, c.port))
	if err != nil {
		return fmt.Errorf("failed to connect to TCP server: %v", err)
	}

	fmt.Printf("Connected to TCP server at %s:%d\n", c.host, c.port)
	return nil
}

func (c *TCPClient) SendMessage(message string) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to server")
	}

    writer := bufio.NewWriter(c.conn)
    if c.wireMode == "line" {
        // line mode
        if _, err := writer.WriteString(message + "\n"); err != nil { return fmt.Errorf("failed to send line: %v", err) }
        if err := writer.Flush(); err != nil { return fmt.Errorf("failed to flush line: %v", err) }
    } else {
        // framed or auto framed send
        if _, err := writer.WriteString(fmt.Sprintf("%d\n", len(message))); err != nil { return fmt.Errorf("failed to send message length: %v", err) }
        if _, err := writer.WriteString(message); err != nil { return fmt.Errorf("failed to send message: %v", err) }
        if err := writer.Flush(); err != nil { return fmt.Errorf("failed to flush message: %v", err) }
    }

	return nil
}

func (c *TCPClient) ReceiveMessage() (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("not connected to server")
	}

	reader := bufio.NewReader(c.conn)

    // Try framed first unless we're explicitly in line mode
    if c.wireMode != "line" {
        if lengthStr, err := reader.ReadString('\n'); err == nil {
            lengthStr = strings.TrimSpace(lengthStr)
            if length, err2 := strconv.Atoi(lengthStr); err2 == nil {
                message := make([]byte, length)
                if _, err = io.ReadFull(reader, message); err != nil { return "", fmt.Errorf("failed to read message: %v", err) }
                return string(message), nil
            } else if c.wireMode == "framed" {
                return "", fmt.Errorf("invalid framed message length: %v", err2)
            } else {
                // auto fallback to line mode using the already read line as the content
                return strings.TrimSpace(lengthStr), nil
            }
        } else if c.wireMode == "framed" {
            return "", fmt.Errorf("failed to read message length: %v", err)
        }
    }
    // line mode: read one line
    line, err := reader.ReadString('\n')
    if err != nil { return "", fmt.Errorf("failed to read line: %v", err) }
    return strings.TrimSpace(line), nil
}

func (c *TCPClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// UDP Server implementation
type UDPServer struct {
	port int
	conn *net.UDPConn
}

func NewUDPServer(port int) *UDPServer {
    return &UDPServer{port: port}
}

func (s *UDPServer) Start() error {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP server: %v", err)
	}

	fmt.Printf("UDP Server listening on port %d\n", s.port)

	buffer := make([]byte, BUFFER_SIZE)

	for {
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}

		message := string(buffer[:n])
		fmt.Printf("Received from %s: %s\n", clientAddr, message)

		// Echo back the message
		response := fmt.Sprintf("Echo: %s", message)
		_, err = s.conn.WriteToUDP([]byte(response), clientAddr)
		if err != nil {
			log.Printf("Error sending UDP response: %v", err)
		}
	}
}

func (s *UDPServer) Stop() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// UDP Client implementation
type UDPClient struct {
	host string
	port int
	conn *net.UDPConn
	serverAddr *net.UDPAddr
}

func NewUDPClient(host string, port int) *UDPClient {
	return &UDPClient{host: host, port: port}
}

func (c *UDPClient) Connect() error {
	var err error
	c.serverAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", c.host, c.port))
	if err != nil {
		return fmt.Errorf("failed to resolve server address: %v", err)
	}

	c.conn, err = net.DialUDP("udp", nil, c.serverAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to UDP server: %v", err)
	}

	fmt.Printf("Connected to UDP server at %s:%d\n", c.host, c.port)
	return nil
}

func (c *UDPClient) SendMessage(message string) error {
	if c.conn == nil {
		return fmt.Errorf("not connected to server")
	}

	_, err := c.conn.Write([]byte(message))
	if err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	return nil
}

func (c *UDPClient) ReceiveMessage() (string, error) {
	if c.conn == nil {
		return "", fmt.Errorf("not connected to server")
	}

	buffer := make([]byte, BUFFER_SIZE)
	n, err := c.conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("failed to receive message: %v", err)
	}

	return string(buffer[:n]), nil
}

func (c *UDPClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func generateLargeMessage(size int) string {
	message := "Large message: "
	remaining := size - len(message)
	for i := 0; i < remaining; i++ {
		message += "A"
	}
	return message
}

func runServer(protocol string, port int, wire string) {
	var server Server

	switch protocol {
	case "tcp":
        if wire == "" { wire = "auto" }
        server = NewTCPServer(port, wire)
	case "udp":
		server = NewUDPServer(port)
	default:
		log.Fatalf("Unsupported protocol: %s", protocol)
	}

	err := server.Start()
	if err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func runClient(protocol string, host string, port int, wire string) {
	var client Client

	switch protocol {
	case "tcp":
        if wire == "" { wire = "auto" }
        client = NewTCPClient(host, port, wire)
	case "udp":
		client = NewUDPClient(host, port)
	default:
		log.Fatalf("Unsupported protocol: %s", protocol)
	}

	err := client.Connect()
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Interactive mode
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("Enter messages (type 'large' for 20KB test, 'quit' to exit):")

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}

		message := scanner.Text()
		if message == "quit" {
			break
		}

		if message == "large" {
			message = generateLargeMessage(LARGE_MESSAGE_SIZE)
			fmt.Printf("Sending large message (%d bytes)\n", len(message))
		}

		err := client.SendMessage(message)
		if err != nil {
			log.Printf("Failed to send message: %v", err)
			continue
		}

		response, err := client.ReceiveMessage()
		if err != nil {
			log.Printf("Failed to receive response: %v", err)
			continue
		}

		fmt.Printf("Response: %s\n", response)
	}
}

func main() {
	var (
		mode     = flag.String("mode", "", "Mode: server or client")
		protocol = flag.String("protocol", "", "Protocol: tcp or udp")
		host     = flag.String("host", "localhost", "Host (for client mode)")
		port     = flag.Int("port", 8080, "Port")
        wire     = flag.String("wire", "auto", "Wire format (tcp only): auto|framed|line")
	)
	flag.Parse()

	if *mode == "" || *protocol == "" {
		fmt.Println("Usage:")
		fmt.Println("  Server mode:")
		fmt.Println("    go run main.go -mode=server -protocol=tcp -port=8080")
		fmt.Println("    go run main.go -mode=server -protocol=udp -port=8080")
		fmt.Println("  Client mode:")
		fmt.Println("    go run main.go -mode=client -protocol=tcp -host=localhost -port=8080")
		fmt.Println("    go run main.go -mode=client -protocol=udp -host=localhost -port=8080")
		os.Exit(1)
	}

    if *mode == "server" {
        runServer(*protocol, *port, *wire)
    } else if *mode == "client" {
        runClient(*protocol, *host, *port, *wire)
	} else {
		log.Fatalf("Invalid mode: %s. Use 'server' or 'client'", *mode)
	}
}
