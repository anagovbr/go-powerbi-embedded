package main

import (
	"embed"
	"log"
	"net/http"
)

//go:embed static index.html
var files embed.FS

func main() {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(files)))
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
