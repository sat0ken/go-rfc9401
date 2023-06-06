package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

func hello(w http.ResponseWriter, req *http.Request) {
	reqb, err := io.ReadAll(req.Body)
	if err != nil {
		log.Println(err)
	}
	defer req.Body.Close()
	
	fmt.Println(string(reqb))
	fmt.Fprintf(w, "hello\n")
}

func main() {

	http.HandleFunc("/", hello)
	http.ListenAndServe("127.0.0.1:18000", nil)
}
