package simplesocks

import (
	"crypto/cipher"
	"io"
	"net"

	"golang.org/x/crypto/chacha20"
)

// Overrides Read() and Write() of net.Conn
type wrappedConn struct {
	net.Conn
	Ingress, Egress cipher.Stream
}

// WrapConn wraps a net.Conn so that Read() decrypts the payload and Write() encrypts the payload.
func WrapConn(conn net.Conn, salt, sharedKey, nonceEgress, nonceIngress []byte) (net.Conn, error) {
	sharedKey, err := chacha20.HChaCha20(sharedKey, salt) // derive key
	if err != nil {
		return nil, err
	}
	egress, err := chacha20.NewUnauthenticatedCipher(sharedKey, nonceEgress)
	if err != nil {
		return nil, err
	}
	ingress, err := chacha20.NewUnauthenticatedCipher(sharedKey, nonceIngress)
	if err != nil {
		return nil, err
	}
	conn = &wrappedConn{
		Conn:    conn,
		Ingress: ingress,
		Egress:  egress,
	}
	return conn, nil
}

func (c *wrappedConn) Read(dst []byte) (n int, err error) {
	n, err = c.Conn.Read(dst)
	c.Ingress.XORKeyStream(dst[:n], dst[:n])
	return
}

func (c *wrappedConn) Write(src []byte) (n int, err error) {
	buf := make([]byte, len(src))
	c.Egress.XORKeyStream(buf, src)
	n, err = c.Conn.Write(buf)
	if n != len(src) && err == nil { // should never happen
		err = io.ErrShortWrite
	}
	return
}
