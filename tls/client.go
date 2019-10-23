package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
)

func newCertPoolFromPEMFile(filename string) (*x509.CertPool, error) {
	cert, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal("ReadFile: ", err)
		return nil, err
	}

	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(cert)
	if !ok {
		log.Fatal("AppendCertsFromPEM: not ok")
		return nil, errors.New("Could not parse certificate")
	}

	return certPool, nil
}

func main() {
	cert, err := tls.LoadX509KeyPair("goClient.crt", "goClient.key")
	if err != nil {
		log.Fatal("LoadX509KeyPair: ", err)
		return
	}

	rootCA, err := newCertPoolFromPEMFile("serverca.pem")
	if err != nil {
		return
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      rootCA,
		ServerName:   "goServer",
	}
	tr := &http.Transport{
		TLSClientConfig: config,
	}
	client := &http.Client{Transport: tr}
	resp, err := client.Get("https://localhost:8443/")
	if err != nil {
		log.Fatal("client.Get: ", err)
		return
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("ReadAll: ", err)
	}

	log.Print(string(body))
}
