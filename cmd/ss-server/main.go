package main

import (
	"flag"
	"io"
	"log"
	"net"

	"github.com/armon/go-socks5"
	"github.com/z-rui/simplesocks"
	"github.com/z-rui/simplesocks/common"
)

var (
	listenAddr  = flag.String("l", "", "listening address")
	dialAddr    = flag.String("d", "", "dial address (leave empty to use built-in SOCKS5 proxy)")
	privKeyPath = flag.String("i", "", "private key path")
)

func main() {
	var err error
	var socksServer *socks5.Server
	flag.Parse()
	if *listenAddr == "" {
		flag.Usage()
		return
	}
	privateKey, err := common.LoadKeyPair(*privKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	if *dialAddr == "" {
		socksServer, err = socks5.New(&socks5.Config{})
		if err != nil {
			log.Fatal(err)
		}
	}
	common.ListenAndServe(*listenAddr, func(conn net.Conn) {
		defer conn.Close()
		in, err := simplesocks.ServerConn(conn, privateKey)
		if err != nil {
			log.Println("Handshake with", conn.RemoteAddr(), "failed:", err)
			return
		}
		if *dialAddr == "" {
			err = socksServer.ServeConn(in)
		} else {
			out, err := net.Dial("tcp", *dialAddr)
			if err != nil {
				log.Println("Dial() failed:", err)
				return
			}
			defer out.Close()
			go io.Copy(out, in)
			io.Copy(in, out)
		}
	})
}
