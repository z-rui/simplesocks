package main

import (
	"flag"
	"io"
	"log"
	"net"

	socks "github.com/fangdingjun/socks-go"
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
	flag.Parse()
	if *listenAddr == "" {
		flag.Usage()
		return
	}
	privateKey, err := LoadKeyPair(*privKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	common.ListenAndServe(*listenAddr, func(conn net.Conn) {
		defer conn.Close()
		in, err := simplesocks.ServerConn(conn, privateKey)
		if err != nil {
			log.Println("Handshake with", conn.RemoteAddr(), "failed:", err)
			return
		}
		if *dialAddr == "" {
			var d net.Dialer
			s := socks.Conn{Conn: in, Dial: d.Dial}
			s.Serve()
		} else {
			out, err := net.Dial("tcp", *dialAddr)
			if err != nil {
				log.Println("Dial() failed:", err)
				return
			}
			defer out.Close()
			go io.Copy(in, out)
			io.Copy(out, in)
		}
	})
}
