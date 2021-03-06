package pathtm

import (
	"encoding/binary"
	"errors"
	"io"
	"time"

	"github.com/busoc/timutil"
)

var (
	ErrEmpty   = errors.New("no data")
	ErrVersion = errors.New("unknown CCSDS version")
)

const BufferSize = 4 << 10

const (
	PTHHeaderLen   = 10
	CCSDSHeaderLen = 6
	ESAHeaderLen   = 10
)

type Packet struct {
	PTHHeader
	CCSDSHeader
	ESAHeader
	Data []byte
	Sum  uint32
}

func (p Packet) Timestamp() time.Time {
	return p.ESAHeader.Timestamp()
}

func (p Packet) Missing(other Packet) int {
	if other.Timestamp().After(p.Timestamp()) {
		return 0
	}
	return p.CCSDSHeader.Missing(other.CCSDSHeader)
}

func (p Packet) Marshal() ([]byte, error) {
	if len(p.Data) == 0 {
		return nil, ErrEmpty
	}
	var offset int
	buf := make([]byte, PTHHeaderLen+CCSDSHeaderLen+int(p.Len()))
	offset += copy(buf[offset:], encodePTH(p.PTHHeader))
	offset += copy(buf[offset:], encodeCCSDS(p.CCSDSHeader))
	if set := (p.CCSDSHeader.Pid >> 11) & 0x1; set != 0 {
		offset += copy(buf[offset:], encodeESA(p.ESAHeader))
	}
	offset += copy(buf[offset:], p.Data)
	return buf, nil
}

type ESAPacketType uint8

const (
	Default ESAPacketType = iota
	DataDump
	DataSegment
	EssentialHk
	SystemHk
	PayloadHk
	ScienceData
	AncillaryData
	EssentialCmd
	SystemCmd
	PayloadCmd
	DataLoad
	Response
	Report
	Exception
	Acknowledge
)

func (e ESAPacketType) Type() string {
	switch e >> 2 {
	default:
		return "***"
	case 0, 1:
		return "dat"
	case 2:
		return "cmd"
	case 3:
		return "evt"
	}
}

func (e ESAPacketType) String() string {
	switch e {
	default:
		return "***"
	case DataDump:
		return "data dump"
	case DataSegment:
		return "data segment"
	case EssentialHk:
		return "essential hk"
	case SystemHk:
		return "system hk"
	case PayloadHk:
		return "payload hk"
	case ScienceData:
		return "science data"
	case AncillaryData:
		return "ancillary data"
	case EssentialCmd:
		return "essential cmd"
	case SystemCmd:
		return "system cmd"
	case PayloadCmd:
		return "payload cmd"
	case DataLoad:
		return "data load"
	case Response:
		return "response"
	case Report:
		return "report"
	case Exception:
		return "exception"
	case Acknowledge:
		return "acknowledge"
	}
}

type CCSDSSegment uint8

func (c CCSDSSegment) String() string {
	switch c {
	default:
		return "***"
	case 0:
		return "continuation"
	case 1:
		return "first"
	case 2:
		return "last"
	case 3:
		return "unsegmented"
	}
}

type PTHHeader struct {
	Size   uint32
	Type   uint8
	Coarse uint32
	Fine   uint8
}

func (p PTHHeader) Timestamp() time.Time {
	t := timutil.Join5(p.Coarse, p.Fine)
	return timutil.GPSTime(t, false)
}

type CCSDSHeader struct {
	Pid      uint16
	Fragment uint16
	Length   uint16
}

func (c CCSDSHeader) Missing(other CCSDSHeader) int {
	if c.Apid() != other.Apid() || c.Sequence() < other.Sequence() {
		return 0
	}
	diff := (c.Sequence() - other.Sequence()) & 0x3FFF
	if diff > 0 {
		diff--
	}
	return int(diff)
}

func (c CCSDSHeader) Len() uint16 {
	return c.Length + 1
}

func (c CCSDSHeader) Apid() uint16 {
	return c.Pid & 0x07FF
}

func (c CCSDSHeader) Sequence() uint16 {
	return c.Fragment & 0x3FFF
}

func (c CCSDSHeader) Segmentation() CCSDSSegment {
	return CCSDSSegment(c.Fragment >> 14)
}

type ESAHeader struct {
	Coarse uint32
	Fine   uint8
	Sid    uint32
	Info   uint8
}

func (e ESAHeader) Timestamp() time.Time {
	return timutil.Join5(e.Coarse, e.Fine)
}

func (e ESAHeader) PacketType() ESAPacketType {
	return ESAPacketType(e.Info & 0xF)
}

func decodePTH(body []byte) (PTHHeader, error) {
	var h PTHHeader
	if len(body) < PTHHeaderLen {
		return h, io.ErrShortBuffer
	}
	h.Size = binary.LittleEndian.Uint32(body)
	h.Type = uint8(body[4])
	h.Coarse = binary.BigEndian.Uint32(body[5:])
	h.Fine = uint8(body[9])

	return h, nil
}

func encodePTH(h PTHHeader) []byte {
	buf := make([]byte, PTHHeaderLen)

	binary.LittleEndian.PutUint32(buf, h.Size)
	buf[4] = byte(h.Type)
	binary.BigEndian.PutUint32(buf[5:], h.Coarse)
	buf[9] = byte(h.Fine)

	return buf
}

func DecodeCCSDS(body []byte) (CCSDSHeader, error) {
	return decodeCCSDS(body)
}

func decodeCCSDS(body []byte) (CCSDSHeader, error) {
	var h CCSDSHeader
	if len(body) < CCSDSHeaderLen {
		return h, io.ErrShortBuffer
	}

	h.Pid = binary.BigEndian.Uint16(body)
	if v := h.Pid >> 13; v != 0 {
		return h, ErrVersion
	}
	h.Fragment = binary.BigEndian.Uint16(body[2:])
	h.Length = binary.BigEndian.Uint16(body[4:])

	return h, nil
}

func encodeCCSDS(c CCSDSHeader) []byte {
	buf := make([]byte, CCSDSHeaderLen)

	binary.BigEndian.PutUint16(buf, c.Pid)
	binary.BigEndian.PutUint16(buf[2:], c.Fragment)
	binary.BigEndian.PutUint16(buf[4:], c.Length)

	return buf
}

func DecodeESA(body []byte) (ESAHeader, error) {
	return decodeESA(body)
}

func decodeESA(body []byte) (ESAHeader, error) {
	var h ESAHeader
	if len(body) < ESAHeaderLen {
		return h, io.ErrShortBuffer
	}

	h.Coarse = binary.BigEndian.Uint32(body)
	h.Fine = uint8(body[4])
	h.Info = uint8(body[5])
	h.Sid = binary.BigEndian.Uint32(body[6:])

	return h, nil
}

func encodeESA(e ESAHeader) []byte {
	buf := make([]byte, ESAHeaderLen)

	binary.BigEndian.PutUint32(buf, e.Coarse)
	buf[4] = byte(e.Fine)
	buf[5] = byte(e.Info)
	binary.BigEndian.PutUint32(buf[6:], e.Sid)

	return buf
}
