package pathtm

import (
	"io"
  "encoding/binary"
  "time"

	"github.com/busoc/timutil"
)

const BufferSize = 4 << 10

const (
	PTHHeaderLen   = 10
	CCSDSHeaderLen = 6
	ESAHeaderLen   = 10
)

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

type Packet struct {
	PTHHeader
	CCSDSHeader
	ESAHeader
	Data []byte
	Sum  uint32
}

type Decoder struct {
	inner  io.Reader
	buffer []byte
}

func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		inner:  r,
		buffer: make([]byte, BufferSize),
	}
}

func DecodePacket(buffer []byte, data bool) (Packet, error) {
	return decodePacket(buffer, data)
}

func (d *Decoder) Decode(data bool) (p Packet, err error) {
	n, err := d.inner.Read(d.buffer)
	if err != nil {
		return
	}
	return decodePacket(d.buffer[:n], data)
}

func decodePacket(body []byte, data bool) (p Packet, err error) {
	var offset int
	if p.PTHHeader, err = decodePTH(body[offset:]); err != nil {
		return
	}
	offset += PTHHeaderLen
	if p.CCSDSHeader, err = decodeCCSDS(body[offset:]); err != nil {
		return
	}
	offset += CCSDSHeaderLen
	if p.ESAHeader, err = decodeESA(body[offset:]); err != nil {
		return
	}
	offset += ESAHeaderLen
	if data {
		p.Data = make([]byte, int(p.CCSDSHeader.Length-ESAHeaderLen))
		copy(p.Data, body[offset:])
	}
	return
}

type PTHHeader struct {
	Size   uint32
	Type   uint8
	Coarse uint32
	Fine   uint8
}

func (p PTHHeader) Timestamp() time.Time {
	return timutil.Join5(p.Coarse, p.Fine)
}

type CCSDSHeader struct {
	Pid      uint16
	Fragment uint16
	Length   uint16
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

func decodeCCSDS(body []byte) (CCSDSHeader, error) {
	var h CCSDSHeader
	if len(body) < CCSDSHeaderLen {
		return h, io.ErrShortBuffer
	}

	h.Pid = binary.BigEndian.Uint16(body)
	h.Fragment = binary.BigEndian.Uint16(body[2:])
	h.Length = binary.BigEndian.Uint16(body[4:])

	return h, nil
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
