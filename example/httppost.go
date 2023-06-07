package main

import (
	"fmt"
	"rfc9401"
)

func main() {
	localhost := "127.0.0.1"
	postdata := "この戦争が終わったらこいつと結婚するんだ"

	resp, err := rfc9401.HttpPost(localhost, localhost, 18000, postdata)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(resp)
}
