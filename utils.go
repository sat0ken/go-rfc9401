package rfc9401

import "encoding/binary"

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
