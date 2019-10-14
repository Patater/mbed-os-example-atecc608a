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

func root(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Hello world!"))
}

func main() {
	rootCA, err := newCertPoolFromPEMFile("serverca.pem")
	if err != nil {
		return
	}

	clientCA, err := newCertPoolFromPEMFile("deviceca.pem")
	if err != nil {
		return
	}

	http.HandleFunc("/", root)
	config := &tls.Config {
		RootCAs: rootCA,
		ClientCAs: clientCA,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	server := &http.Server {
		Addr: ":8443",
		TLSConfig: config,
	}
	err = server.ListenAndServeTLS("goServer.crt", "goServer.key")
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
}
