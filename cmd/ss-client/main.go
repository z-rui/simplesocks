package main

import (
	"encoding/base64"
	"flag"
	"io"
	"log"
	"net"

	"github.com/z-rui/simplesocks"
	"github.com/z-rui/simplesocks/common"
	"github.com/z-rui/simplesocks/x25519"
)

var (
	listenAddr       = flag.String("l", ":1080", "listening address")
	dialAddr         = flag.String("d", "", "dial address")
	privKeyPath      = flag.String("i", "", "private key path")
	peerPubkeyBase64 = flag.String("k", "", "base64-encoded server public key")
)

type pubKey []byte

func (pk pubKey) PublicKey() []byte { return []byte(pk) }

func main() {
	var err error
	flag.Parse()
	if *dialAddr == "" || *peerPubkeyBase64 == "" {
		flag.Usage()
		return
	}
	privateKey, err := common.LoadKeyPair(*privKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	serverKey, err := base64.StdEncoding.DecodeString(*peerPubkeyBase64)
	if err != nil || len(serverKey) != x25519.PublicKeySize {
		log.Fatal("bad public key")
	}
	common.ListenAndServe(*listenAddr, func(conn net.Conn) {
		defer conn.Close()
		peer, err := net.Dial("tcp", *dialAddr)
		if err != nil {
			log.Println("Dial to ", *dialAddr, " failed:", err)
			return
		}
		defer peer.Close()
		peer, err = simplesocks.ClientConn(peer, privateKey, pubKey(serverKey))
		if err != nil {
			log.Println("Handshake with", peer.RemoteAddr(), "failed:", err)
			return
		}
		go io.Copy(peer, conn)
		io.Copy(conn, peer)
	})
}
