package main

import (
	"rfc9401"
)

func main() {
	tcpstate := make(chan rfc9401.TcpState)
	rfc9401.Listen("127.0.0.1", 18000, tcpstate)

	//rfc9401.ListenAndServeHTTP("127.0.0.1", 18000)
}
