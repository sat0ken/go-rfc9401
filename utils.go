package rfc9401

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func uint16ToByte(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

func byteToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func uint32ToByte(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
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

func ipv4To4Byte(ipv4 string) [4]byte {
	var b [4]byte
	str := strings.Split(ipv4, ".")
	for index, v := range str {
		i, _ := strconv.Atoi(v)
		b[index] = byte(i)
	}
	return b
}

func ipv4ByteToString(ipv4 []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ipv4[0], ipv4[1], ipv4[2], ipv4[3])
}

func getRandomClientPort() int {
	rand.Seed(time.Now().UnixNano())
	min := 50000
	max := 60000
	return rand.Intn(max-min+1) + min
}

func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func sendsocket() (int, error) {
	soc, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("Create Socket err : %s", err)
	}
	return soc, nil
}

func recvsocket(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return -1, fmt.Errorf("Create Socket err : %s", err)
	}
	// socketにインターフェイスをbindする
	addr := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  index,
	}
	err = syscall.Bind(sock, &addr)
	if err != nil {
		return -1, fmt.Errorf("bind err : %v", err)
	}
	return sock, nil
}
