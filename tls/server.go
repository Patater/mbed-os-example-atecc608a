package main

import (
	"log"
	"net/http"
)

func root(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("Hello world!"))
}

func main() {
	http.HandleFunc("/", root)
	err := http.ListenAndServeTLS(
		":8080",
		"server1.crt",
		"server1.key",
		nil)
	if err != nil {
		log.Fatal("ListenAndServeTLS: ", err)
	}
}
