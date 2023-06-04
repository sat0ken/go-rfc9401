package rfc9401

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

func uint16ToByte(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

func uint32ToByte(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

func byteToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func byteToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func sumByteArr(packet []byte) (sum uint) {
	for i, _ := range packet {
		if i%2 == 0 {
			sum += uint(byteToUint16(packet[i:]))
		}
	}
	return sum
}

func calcChecksum(packet []byte) []byte {
	// まず16ビット毎に足す
	sum := sumByteArr(packet)
	// あふれた桁を足す
	sum = (sum & 0xffff) + sum>>16
	// 論理否定を取った値をbyteにして返す
	return uint16ToByte(uint16(sum ^ 0xffff))
}

func addAckNumber(ack []byte, add uint32) []byte {
	intack := byteToUint32(ack)
	intack += add
	return uint32ToByte(intack)
}

func ipv4ToByte(ipv4 string) []byte {
	var b bytes.Buffer
	str := strings.Split(ipv4, ".")
	for _, v := range str {
		i, _ := strconv.Atoi(v)
		b.Write([]byte{byte(i)})
	}
	return b.Bytes()
}

func ipv4ByteToString(ipv4 []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
}

func getRandomClientPort() int {
	rand.Seed(time.Now().UnixNano())
	min := 30000
	max := 60000
	return rand.Intn(max-min+1) + min
}

func CreateHttpGet(server string, port int) []byte {

	reqstr := "GET / HTTP/1.1\n"
	reqstr += fmt.Sprintf("Host: %s:%d\n", server, port)
	reqstr += "User-Agent: curl/7.81.0\n"
	// reqstr += "Connection: close\n"
	reqstr += "Accept: */*\n\n"

	return []byte(reqstr)
}
