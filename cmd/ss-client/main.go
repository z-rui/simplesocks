package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"

	"github.com/z-rui/simplesocks"
	"github.com/z-rui/simplesocks/x25519"
)

var (
	listenAddr       = flag.String("l", ":1080", "listening address")
	dialAddr         = flag.String("d", "", "dial address")
	peerPubkeyBase64 = flag.String("k", "", "base64-encoded server public key")
)

var (
	privateKey *x25519.PrivateKey
	serverKey  []byte
)

func main() {
	var err error
	flag.Parse()
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if *listenAddr == "" || *dialAddr == "" || *peerPubkeyBase64 == "" {
		flag.Usage()
		return
	}
	privateKey, err = x25519.NewPrivate(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	serverKey, err = base64.StdEncoding.DecodeString(*peerPubkeyBase64)
	if err != nil || len(serverKey) != x25519.PublicKeySize {
		log.Fatal("bad public key")
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
	peer, err := net.Dial("tcp", *dialAddr)
	if err != nil {
		log.Println(err)
		return
	}
	defer peer.Close()
	peer, err = simplesocks.ClientConn(peer, privateKey, serverKey)
	if err != nil {
		log.Println("Handshake failed:", err)
		return
	}
	go io.Copy(conn, peer)
	io.Copy(peer, conn)
}
