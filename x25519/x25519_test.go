package x25519

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

const pemKey = "-----BEGIN PRIVATE KEY-----\n" +
	"MC4CAQAwBQYDK2VuBCIEIGjgkIt+VrA0i34q7FJ6bOaQSBEPNixESiVDvRd+28dM\n" +
	"-----END PRIVATE KEY-----\n"

var privKey = []byte{
	0x68, 0xe0, 0x90, 0x8b, 0x7e, 0x56, 0xb0, 0x34,
	0x8b, 0x7e, 0x2a, 0xec, 0x52, 0x7a, 0x6c, 0xe6,
	0x90, 0x48, 0x11, 0x0f, 0x36, 0x2c, 0x44, 0x4a,
	0x25, 0x43, 0xbd, 0x17, 0x7e, 0xdb, 0xc7, 0x4c,
}

func TestDecodePrivate(t *testing.T) {
	var k PrivateKey

	err := k.ParsePEM([]byte(pemKey))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.PrivateKey(), privKey) {
		t.Error("key mismatch, got: ", k.PrivateKey())
	}
}

func TestEncodePrivate(t *testing.T) {
	k := new(PrivateKey)
	k.SetBytes(privKey)
	block, err := k.EncodePEM()
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(block)
	if !bytes.Equal(data, []byte(pemKey)) {
		t.Error("PEM mismatch, got: ", string(data))
	}
}

func TestPassword(t *testing.T) {
	password := []byte("hello, world")
	k := new(PrivateKey)
	k.SetBytes(privKey)
	block, err := k.EncodePEMWithPassword(rand.Reader, password, x509.PEMCipherAES128)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(block)
	k = new(PrivateKey)
	err = k.ParsePEMWithPassword(data, password)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k.PrivateKey(), privKey) {
		t.Error("key mismatch, got: ", k.PrivateKey())
	}
	err = k.ParsePEMWithPassword(data, []byte("wrong"))
	if err != x509.IncorrectPasswordError {
		t.Error("didn't report incorrect password")
	}
}
