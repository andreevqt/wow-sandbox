package main

import (
	"log"
	"net"

	"wowsandbox/internal/account"
	"wowsandbox/internal/auth"
)

func main() {
	store := account.NewStore()
	store.Register("TEST", "TEST")
	log.Printf("registered test account: TEST / TEST")

	ln, err := net.Listen("tcp", ":3724")
	if err != nil {
		log.Fatalf("listen :3724: %v", err)
	}
	log.Printf("logon server listening on :3724 (realm -> %s)", auth.WorldAddress)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		log.Printf("connection from %s", conn.RemoteAddr())
		go auth.NewSession(conn, store).Handle()
	}
}
