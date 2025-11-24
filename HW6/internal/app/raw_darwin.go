package app

import "fmt"

func openRawSocket(name string) (*rawSocket, error) {
	return nil, fmt.Errorf("raw sockets are supported on Linux only (interface %s)", name)
}

func (r *rawSocket) Close() error {
	return nil
}

func (r *rawSocket) send(_ []byte) error {
	return fmt.Errorf("raw sockets are unavailable on this platform")
}
