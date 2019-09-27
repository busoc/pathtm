package pathtm

import (
	"io"
	"time"
)

type Decoder struct {
	filter func(CCSDSHeader, ESAHeader) (bool, error)
	inner  io.Reader
	buffer []byte
}

func NewDecoder(r io.Reader, filter func(CCSDSHeader, ESAHeader) (bool, error)) *Decoder {
	if filter == nil {
		filter = func(_ CCSDSHeader, _ ESAHeader) (bool, error) {
			return true, nil
		}
	}
	return &Decoder{
		filter: filter,
		inner:  r,
		buffer: make([]byte, BufferSize),
	}
}

func (d *Decoder) Marshal() ([]byte, time.Time, error) {
	p, err := d.Decode(true)
	if err != nil {
		return nil, time.Time{}, err
	}
	buf, err := p.Marshal()
	return buf, p.Timestamp(), err
}

func (d *Decoder) Decode(data bool) (p Packet, err error) {
	var ok bool
	for {
		p, ok, err = d.nextPacket(data)
		if ok || err != nil {
			break
		}
	}
	return
}

func (d *Decoder) nextPacket(data bool) (p Packet, keep bool, err error) {
	var n int
	if n, err = d.inner.Read(d.buffer); err != nil {
		return
	}
	if p, err = decodePacket(d.buffer[:n], data); err != nil {
		return
	}
	keep, err = d.filter(p.CCSDSHeader, p.ESAHeader)
	return
}

func DecodePacket(buffer []byte, data bool) (Packet, error) {
	return decodePacket(buffer, data)
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
	if set := (p.Pid >> 11) & 0x1; set != 0 {
		if p.ESAHeader, err = decodeESA(body[offset:]); err != nil {
			return
		}
		offset += ESAHeaderLen
	}
	if data {
		p.Data = make([]byte, int(p.CCSDSHeader.Len()-ESAHeaderLen))
		copy(p.Data, body[offset:])
	}
	return
}
