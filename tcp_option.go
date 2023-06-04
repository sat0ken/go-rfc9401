package rfc9401

import "bytes"

const (
	TCP_Option_No_Operation         = 1
	TCP_OPTION_Maximum_Segment_Size = 2
	TCP_Option_Window_Scale         = 3
	TCP_Option_SACK_Permitted       = 4
	TCP_Option_SACK                 = 5
	TCP_Option_Timestamps           = 8
)

type tcpOptions struct {
	// No Operation
	nop struct {
		kind uint8
	}
	// Maximum Segment Size
	mss struct {
		kind   uint8
		length uint8
		value  uint16
	}
	// Window Scale
	windowscale struct {
		kind       uint8
		length     uint8
		shiftcount uint8
	}
	// SACK Permitted
	sackpermitted struct {
		kind   uint8
		length uint8
	}
	// Timestamps
	timestamp struct {
		kind   uint8
		length uint8
		value  uint32
		replay uint32
	}
}

func parseTCPOptions(packetOpts []byte) tcpOptions {
	var tcpopt tcpOptions

	for {
		if len(packetOpts) == 0 {
			break
		} else {
			switch packetOpts[0] {
			case TCP_OPTION_Maximum_Segment_Size:
				tcpopt.mss.kind = packetOpts[0]
				tcpopt.mss.length = packetOpts[1]
				tcpopt.mss.value = byteToUint16(packetOpts[2:4])
				packetOpts = packetOpts[4:]
			case TCP_Option_SACK_Permitted:
				tcpopt.sackpermitted.kind = packetOpts[0]
				tcpopt.sackpermitted.length = packetOpts[1]
				packetOpts = packetOpts[2:]
			case TCP_Option_Timestamps:
				tcpopt.timestamp.kind = packetOpts[0]
				tcpopt.timestamp.length = packetOpts[1]
				tcpopt.timestamp.value = byteToUint32(packetOpts[2:6])
				tcpopt.timestamp.replay = byteToUint32(packetOpts[6:10])
				packetOpts = packetOpts[10:]
			case TCP_Option_No_Operation:
				tcpopt.nop.kind = packetOpts[0]
				packetOpts = packetOpts[1:]
			case TCP_Option_Window_Scale:
				tcpopt.windowscale.kind = packetOpts[0]
				tcpopt.windowscale.length = packetOpts[1]
				tcpopt.windowscale.shiftcount = packetOpts[2]
				packetOpts = packetOpts[3:]
			}
		}
	}

	return tcpopt
}

func (options *tcpOptions) optSYN() []byte {
	var b bytes.Buffer

	opt := tcpOptions{
		mss: struct {
			kind   uint8
			length uint8
			value  uint16
		}{kind: TCP_OPTION_Maximum_Segment_Size, length: 4, value: 65495},
		sackpermitted: struct {
			kind   uint8
			length uint8
		}{kind: TCP_Option_SACK_Permitted, length: 2},
		timestamp: struct {
			kind   uint8
			length uint8
			value  uint32
			replay uint32
		}{kind: TCP_Option_Timestamps, length: 10, value: 3766008248, replay: 0},
		nop: struct{ kind uint8 }{kind: TCP_Option_No_Operation},
		windowscale: struct {
			kind       uint8
			length     uint8
			shiftcount uint8
		}{kind: TCP_Option_Window_Scale, length: 3, shiftcount: 7},
	}
	// Maximum Segment Size
	b.Write([]byte{opt.mss.kind, opt.mss.length})
	b.Write(uint16ToByte(opt.mss.value))
	// SACK Permitted
	b.Write([]byte{opt.sackpermitted.kind, opt.sackpermitted.length})
	// Timestamps
	b.Write([]byte{opt.timestamp.kind, opt.timestamp.length})
	b.Write(uint32ToByte(opt.timestamp.value))
	b.Write(uint32ToByte(opt.timestamp.replay))
	// No Operation
	b.Write([]byte{opt.nop.kind})
	// Window Scale
	b.Write([]byte{opt.windowscale.kind, opt.windowscale.length, opt.windowscale.shiftcount})

	return b.Bytes()
}

func (options *tcpOptions) optACK(tsval uint32) []byte {
	var b bytes.Buffer
	opt := tcpOptions{
		timestamp: struct {
			kind   uint8
			length uint8
			value  uint32
			replay uint32
		}{kind: TCP_Option_Timestamps, length: 10, value: tsval, replay: tsval},
	}
	b.Write([]byte{TCP_Option_No_Operation, TCP_Option_No_Operation})
	b.Write([]byte{opt.timestamp.kind, opt.timestamp.length})
	b.Write(uint32ToByte(opt.timestamp.value))
	b.Write(uint32ToByte(opt.timestamp.replay))

	return b.Bytes()
}
