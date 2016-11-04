package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	//"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

func RSASign(privateKeyFile string, hash crypto.Hash, msg []byte) ([]byte, error) {
	c, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode([]byte(c))
	if p == nil {
		return nil, errors.New("decode pem failed...")
	}

	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	h.Write(msg)
	hashed := h.Sum(nil)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key.(*rsa.PrivateKey), hash, hashed[:])
	return sig, err
}

func RSAVerify(pubKeyFile string, hash crypto.Hash, msg []byte, sig []byte) error {
	c, err := ioutil.ReadFile(pubKeyFile)
	if err != nil {
		return err
	}

	p, _ := pem.Decode([]byte(c))
	if p == nil {
		return errors.New("decode pem failed...")
	}

	key, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return err
	}

	h := hash.New()
	h.Write(msg)
	hashed := h.Sum(nil)

	return rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), hash, hashed[:], sig)
}

/*
	log.Printf("Signature: %x\n", signature)
	signature_encoded := base64.StdEncoding.EncodeToString(signature)
	log.Printf("%s\n", signature_encoded)

    encoded := base64.StdEncoding.EncodeToString([]byte(msg))
    decoded, err := base64.StdEncoding.DecodeString(encoded)
    err := VerifyPKCS1v15(&rsaPrivateKey.PublicKey, crypto.SHA256, hashed[:], signature)
*/

func main() {
	msg := "hello golang"
	sig, err := RSASign("pkcs8_rsa_private_key.pem", crypto.SHA256, []byte(msg))
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%x\n", sig)
		err := RSAVerify("rsa_public_key.pem", crypto.SHA256, []byte(msg), sig)
		fmt.Println(err)
	}
}
