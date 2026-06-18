package main

import (
	"log"
	"net"

	"wowsandbox/internal/account"
	"wowsandbox/internal/auth"
	"wowsandbox/internal/session"
	"wowsandbox/internal/world"
)

func main() {
	accounts := account.NewStore()
	accounts.Register("TEST", "TEST")
	sessions := session.NewStore()
	log.Printf("registered test account: TEST / TEST")

	go serveLogon(accounts, sessions)
	serveWorld(sessions) // blocks
}

func serveLogon(accounts *account.Store, sessions *session.Store) {
	ln, err := net.Listen("tcp", ":3724")
	if err != nil {
		log.Fatalf("listen :3724: %v", err)
	}
	log.Printf("logon server listening on :3724")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("logon accept: %v", err)
			continue
		}
		log.Printf("logon connection from %s", conn.RemoteAddr())
		go auth.NewSession(conn, accounts, sessions).Handle()
	}
}

func serveWorld(sessions *session.Store) {
	ln, err := net.Listen("tcp", ":8085")
	if err != nil {
		log.Fatalf("listen :8085: %v", err)
	}
	log.Printf("world server listening on :8085")
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("world accept: %v", err)
			continue
		}
		log.Printf("world connection from %s", conn.RemoteAddr())
		go world.NewSession(conn, sessions).Handle()
	}
}
