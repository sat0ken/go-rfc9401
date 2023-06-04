package main

import (
	"rfc9401"
)

func main() {
	//tcpstate := make(chan rfc9401.TcpState)
	//err := rfc9401.Listen("127.0.0.1", 18000, tcpstate)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//tcpheader := <-tcpstate
	//fmt.Printf("tcp header is %+v\n", tcpheader)
	rfc9401.ListenAndServeHTTP("127.0.0.1", 18000)
}
