package x25519

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
)

const (
	PrivateKeySize = curve25519.PointSize
	PublicKeySize  = curve25519.PointSize
)

type PrivateKey struct {
	key    [PrivateKeySize]byte
	pubkey [PublicKeySize]byte
}

func (k *PrivateKey) PrivateKey() []byte {
	return k.key[:]
}

func (k *PrivateKey) PublicKey() []byte {
	return k.pubkey[:]
}

func (k *PrivateKey) SharedKey(peer []byte) ([]byte, error) {
	return curve25519.X25519(k.key[:], peer)
}

func (k *PrivateKey) SetBytes(data []byte) *PrivateKey {
	if len(data) != PrivateKeySize {
		panic("key size not match")
	}
	copy(k.key[:], data)
	// RFC 7448
	k.key[0x00] &= 0xf8
	k.key[0x1f] &= 0x7f
	k.key[0x1f] |= 0x40
	pk, err := curve25519.X25519(k.key[:], curve25519.Basepoint)
	if err != nil {
		panic(err)
	}
	copy(k.pubkey[:], pk)
	return k
}

func NewPrivate(rand io.Reader) (k *PrivateKey, err error) {
	var buf [PrivateKeySize]byte
	_, err = io.ReadFull(rand, buf[:])
	if err != nil {
		return nil, err
	}
	k = new(PrivateKey)
	k.SetBytes(buf[:])
	return
}

var (
	OID             = asn1.ObjectIdentifier([]int{1, 3, 101, 110})
	ErrBadOID       = errors.New("bad ASN.1 object identifier")
	ErrNotFound     = errors.New("no private key found")
	ErrSizeMismatch = errors.New("key size mismatch")
)

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func (k *PrivateKey) ParsePKCS8(der []byte) error {
	var data pkcs8
	_, err := asn1.Unmarshal(der, &data)
	if err != nil {
		return err
	}
	if !data.Algo.Algorithm.Equal(OID) {
		return ErrBadOID
	}
	var buf []byte
	_, err = asn1.Unmarshal(data.PrivateKey, &buf)
	if err != nil {
		return err
	}
	if len(buf) != PrivateKeySize {
		return ErrSizeMismatch
	}
	k.SetBytes(buf)
	return nil
}

func (k *PrivateKey) EncodePKCS8() ([]byte, error) {
	buf, err := asn1.Marshal(k.key[:])
	if err != nil {
		return nil, err
	}
	data := pkcs8{
		Version: 0,
		Algo: pkix.AlgorithmIdentifier{
			Algorithm: OID,
		},
		PrivateKey: buf,
	}
	return asn1.Marshal(data)
}

const pemPrivateKeyType = "PRIVATE KEY"

func (k *PrivateKey) ParsePEM(data []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return ErrNotFound
	}
	if x509.IsEncryptedPEMBlock(block) {
		return x509.IncorrectPasswordError
	}
	return k.ParsePKCS8(block.Bytes)
}

func (k *PrivateKey) ParsePEMWithPassword(data, password []byte) error {
	block, _ := pem.Decode(data)
	if block == nil {
		return ErrNotFound
	}
	if !x509.IsEncryptedPEMBlock(block) {
		return x509.IncorrectPasswordError
	}
	data, err := x509.DecryptPEMBlock(block, password)
	if err != nil {
		return err
	}
	return k.ParsePKCS8(data)
}

func (k *PrivateKey) EncodePEM() (block *pem.Block, err error) {
	der, err := k.EncodePKCS8()
	if err != nil {
		return
	}
	block = &pem.Block{
		Type:  pemPrivateKeyType,
		Bytes: der,
	}
	return
}

func (k *PrivateKey) EncodePEMWithPassword(rand io.Reader, password []byte, cipher x509.PEMCipher) (block *pem.Block, err error) {
	der, err := k.EncodePKCS8()
	if err != nil {
		return
	}
	return x509.EncryptPEMBlock(rand, pemPrivateKeyType, der, password, cipher)
}
