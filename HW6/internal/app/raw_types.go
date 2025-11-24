package app

import "syscall"

type rawSocket struct {
	fd       int
	name     string
	ifindex  int
	sendAddr syscall.Sockaddr
}
