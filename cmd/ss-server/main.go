package main

import (
	"flag"
	"io"
	"log"
	"net"

	socks "github.com/fangdingjun/socks-go"
	"github.com/z-rui/simplesocks"
	"github.com/z-rui/simplesocks/x25519"
)

var (
	listenAddr  = flag.String("l", "", "listening address")
	dialAddr    = flag.String("d", "", "dial address (leave empty to use built-in SOCKS5 proxy)")
	privKeyPath = flag.String("i", "", "private key path")
)

var (
	privateKey *x25519.PrivateKey
)

func main() {
	var err error
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if *listenAddr == "" {
		flag.Usage()
		return
	}
	privateKey, err = LoadKeyPair(*privKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("Listening on", *listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Accept() failed:", err)
			continue
		}
		conn.(*net.TCPConn).SetNoDelay(false)
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	in, err := simplesocks.ServerConn(conn, privateKey)
	if err != nil {
		log.Println("Handshake failed:", err)
		return
	}
	if *dialAddr == "" {
		var d net.Dialer
		s := socks.Conn{Conn: in, Dial: d.Dial}
		s.Serve()
	} else {
		out, err := net.Dial("tcp", *dialAddr)
		if err != nil {
			log.Println(err)
			return
		}
		defer out.Close()
		go io.Copy(in, out)
		io.Copy(out, in)
	}
}
