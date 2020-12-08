package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/z-rui/simplesocks/x25519"
	"golang.org/x/term"
)

func askpass(prompt string) []byte {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil
	}
	io.WriteString(os.Stdout, prompt)
	data, err := term.ReadPassword(fd)
	if err != nil {
		return nil
	}
	io.WriteString(os.Stdout, "\n")
	return data
}

func LoadPrivateKey(filename string, retry int) (*x25519.PrivateKey, error) {
	k := new(x25519.PrivateKey)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	err = k.ParsePEM(data)
	if err == x509.IncorrectPasswordError {
		for ; retry > 0; retry-- {
			err = k.ParsePEMWithPassword(data, askpass("Password: "))
			if err == nil {
				return k, nil
			}
			if err != x509.IncorrectPasswordError {
				break
			}
		}
	}
	return k, err
}

func SavePrivateKey(filename string, key *x25519.PrivateKey) error {
	var block *pem.Block
	var err error
	password := askpass("Password: ")
	if len(password) != 0 {
		if !bytes.Equal(password, askpass("Confirm password: ")) {
			return errors.New("password mismatch")
		}
		block, err = key.EncodePEMWithPassword(rand.Reader, password, x509.PEMCipherAES256)
	} else {
		block, err = key.EncodePEM()
	}
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(block)
	const fileMode = 0600
	return ioutil.WriteFile(filename, data, fileMode)
}

func LoadKeyPair(filename string) (priv *x25519.PrivateKey, err error) {
	if filename != "" {
		const maxRetry = 3
		priv, err = LoadPrivateKey(filename, maxRetry)
		if os.IsNotExist(err) {
			log.Print("Generating new key")
			priv, err = x25519.NewPrivate(rand.Reader)
			if err == nil {
				err = SavePrivateKey(filename, priv)
			}
		}
	} else {
		log.Print("Generating ephemeral key")
		priv, err = x25519.NewPrivate(rand.Reader)
	}
	if err == nil {
		log.Println("My public key:", base64.StdEncoding.EncodeToString(priv.PublicKey()))
	}
	return
}
