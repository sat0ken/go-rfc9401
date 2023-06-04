package rfc9401

import (
	"fmt"
	"strconv"
	"strings"
)

type HttpHeader struct {
	Key   string
	Value string
}

type HttpHeaderBody struct {
	Status  int
	Headers []HttpHeader
	Body    string
}

func CreateHttpGet(server string, port int) []byte {

	reqstr := "GET / HTTP/1.1\n"
	reqstr += fmt.Sprintf("Host: %s:%d\n", server, port)
	reqstr += "User-Agent: curl/7.81.0\n"
	// reqstr += "Connection: close\n"
	reqstr += "Accept: */*\n\n"

	return []byte(reqstr)
}

func CreateHttpResp(data string) []byte {

	respbody := "HTTP/1.1 200 OK\r\n"
	respbody += "Date: Sun, 04 Jun 2023 10:15:28 GMT\r\n"
	respbody += fmt.Sprintf("Content-Length: %d\r\n", len(data))
	respbody += "Content-Type: text/plain; charset=utf-8\r\n\r\n"
	respbody += data

	return []byte(respbody)
}

func ParseHTTP(httpbyte string) (http HttpHeaderBody) {

	spiltstr := strings.Split(httpbyte, "\r\n")
	for _, v := range spiltstr {
		// HTTP1.1のみ対応
		if strings.HasPrefix(v, "HTTP/1.1") {
			tmp := strings.Split(v, " ")
			status, _ := strconv.Atoi(tmp[1])
			http.Status = status
		}
		if strings.Contains(v, ": ") {
			tmp := strings.Split(v, ": ")
			http.Headers = append(http.Headers, HttpHeader{
				Key:   tmp[0],
				Value: tmp[1],
			})
			if tmp[0] == "Content-Length" {
				bodylen, _ := strconv.Atoi(tmp[1])
				http.Body = httpbyte[len(httpbyte)-bodylen:]
			}
		}

	}

	return http
}

func HttpGet(client, server string, port int) (string, error) {

	conn, err := Dial(client, server, port)
	if err != nil {
		return "", err
	}

	conn, data, err := conn.Write(CreateHttpGet(server, port))
	if err != nil {
		return "", err
	}
	if conn.DTH == 1 {
		err = fmt.Errorf("TCPセッションに死亡フラグが立ちました")
	}

	// conn.Close()

	return string(data), err
}

func ListenAndServeHTTP(listenAddr string, port int) error {
	chHeader := make(chan TcpState)
	go func() {
		Listen(listenAddr, port, chHeader)
	}()
	for {
		result := <-chHeader
		if result.err != nil {
			return result.err
		}
		fmt.Printf("ListenAndServeHTTP result header is %+v\n", result.tcpHeader)
	}
}
