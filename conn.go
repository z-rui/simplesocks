package simplesocks

import (
	"crypto/rand"
	"io"
	"net"

	"github.com/z-rui/simplesocks/x25519"
)

/* Protocol
 *
 * Server's public key is static (known to client)
 *
 * Handshake: client sends 72B to server:
 * - salt: 16B
 * - nonce1: (12B)
 * - nonce2: (12B)
 * - XOR(client_public, {salt,salt}): (32B)
 *
 * shared_key' = X25519(client_priv, server_public) = X25519(server_priv, client_public)
 * shared_key = HChaCha20(shared_key', salt)
 *
 * client->server uses stream cipher ChaCha20(sharedKey, nonce1)
 * server->client uses stream cipher ChaCha20(sharedKey, nonce2)
 */

const (
	saltSize    = 16
	nonceSize   = 12
	pubkeySize  = x25519.PublicKeySize
	entropySize = saltSize + nonceSize*2
	headerSize  = entropySize + pubkeySize
)

// ClientConn wraps an outgoing connection to the server: handshake and encrypt all traffic
func ClientConn(conn net.Conn, local *x25519.PrivateKey, peer []byte) (net.Conn, error) {
	var header [headerSize]byte
	_, err := rand.Read(header[:entropySize])
	if err != nil {
		return nil, err
	}
	for i, b := range local.PublicKey() {
		header[entropySize+i] = b ^ header[i%saltSize]
	}
	_, err = conn.Write(header[:])
	if err != nil {
		return nil, err
	}
	salt := header[2*nonceSize : 2*nonceSize+saltSize]
	nonce1 := header[:nonceSize]
	nonce2 := header[nonceSize : 2*nonceSize]
	sharedKey, err := local.SharedKey(peer)
	return WrapConn(conn, salt, sharedKey, nonce1, nonce2)
}

// ServerConn wraps an incoming connection from the client: handshake and encrypt all traffic
func ServerConn(conn net.Conn, local *x25519.PrivateKey) (net.Conn, error) {
	const entropySize = nonceSize*2 + saltSize
	var header [headerSize]byte
	_, err := io.ReadFull(conn, header[:])
	if err != nil {
		return nil, err
	}
	pk := header[entropySize:]
	for i, b := range pk {
		pk[i] = b ^ header[i%saltSize]
	}
	salt := header[2*nonceSize : 2*nonceSize+saltSize]
	nonce1 := header[:nonceSize]
	nonce2 := header[nonceSize : 2*nonceSize]
	sharedKey, err := local.SharedKey(pk)
	return WrapConn(conn, salt, sharedKey, nonce2, nonce1)
}
