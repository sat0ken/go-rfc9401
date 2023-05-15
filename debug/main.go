package main

import (
	"log"
	"rfc9401"
)

func main() {
	tcpHeader, err := rfc9401.Dial("127.0.0.1", "127.0.0.1", 18080)
	if err != nil {
		log.Fatalf("Client connection is error : %v", err)
	}
	err = tcpHeader.Write([]byte(`hoge`))
	if err != nil {
		log.Fatalf("Write error : %v", err)
	}
}
