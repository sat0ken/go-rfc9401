package main

import (
	"fmt"
	"log"
	"rfc9401"
)

func main() {
	localhost := "127.0.0.1"
	resp, err := rfc9401.HttpGet(localhost, localhost, 18000)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp)
}
