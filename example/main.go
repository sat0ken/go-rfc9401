package main

import (
	"log"
	"rfc9401"
)

func main() {
	conn, err := rfc9401.Dial("127.0.0.1", "127.0.0.1", 18080)
	if err != nil {
		log.Fatalf("Client connection is error : %v", err)
	}

	//for i := 0; i < 3; i++ {
	conn, err = conn.Write([]byte{0x68, 0x6f, 0x67, 0x65, 0x0a})
	if err != nil {
		log.Fatalf("Write error : %v", err)
	}
	//}

	conn.Close()
}
