package common

import (
	"log"
	"net"
)

func ListenAndServe(addr string, handleConnection func(net.Conn)) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Listening on", addr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept() failed.")
			continue
		}
		go handleConnection(conn)
	}
}
