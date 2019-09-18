package main

import (
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
)

func runMerge(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	files := cmd.Flag.Args()
	w, err := os.Create(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer w.Close()

	return rt.MergeFiles(files[1:], w, func(bs []byte) (rt.Offset, error) {
		var o rt.Offset
		if len(bs) < pathtm.PTHHeaderLen+pathtm.ESAHeaderLen {
			return o, rt.ErrSkip
		}
		if c, err := pathtm.DecodeCCSDS(bs[pathtm.PTHHeaderLen:]); err != nil {
			return o, err
		} else {
			o.Pid, o.Sequence = uint(c.Apid()), uint(c.Sequence())
		}
		if e, err := pathtm.DecodeESA(bs[pathtm.PTHHeaderLen+pathtm.CCSDSHeaderLen:]); err != nil {
			return o, err
		} else {
			o.Time = e.Timestamp()
		}
		return o, nil
	})
}

type writer struct {
	format   rt.Formatter
	interval time.Duration
	writers  map[uint16]*os.File
	times    map[uint16]time.Time
}

func NewWriter(str string, interval time.Duration) (*writer, error) {
	f, err := rt.Parse(str)
	if err != nil {
		return nil, err
	}
	w := writer{
		format:   f,
		interval: interval,
		writers:  make(map[uint16]*os.File),
		times:    make(map[uint16]time.Time),
	}
	return &w, nil
}

func (w *writer) Close() error {
	var err error
	for _, c := range w.writers {
		e := c.Close()
		if err == nil && e != nil {
			err = e
		}
	}
	return err
}

func (w *writer) WritePacket(p pathtm.Packet) error {
	apid := p.Apid()
	when := p.Timestamp().Truncate(w.interval)

	stamp := w.times[apid]
	if stamp.IsZero() {
		w.times[apid], stamp = when, when

		pi := rt.PacketInfo{
			Pid:  int(apid),
			Sid:  int(p.ESAHeader.Sid),
			When: when,
		}
		file := w.format.Format(pi)
		if err := os.MkdirAll(filepath.Dir(file), 0755); err != nil {
			return err
		}
		wc, err := os.Create(file)
		if err != nil {
			return err
		}
		w.writers[apid] = wc
	}
	if delta := when.Sub(stamp); delta >= w.interval {
		if err := w.writers[apid].Close(); err != nil {
			return err
		}
		delete(w.times, apid)
		delete(w.writers, apid)
		return w.WritePacket(p)
	}
	buf, err := p.Marshal()
	if err == nil {
		_, err = w.writers[apid].Write(buf)
	}
	return err
}

func runTake(cmd *cli.Command, args []string) error {
	var (
		apid     = cmd.Flag.Int("p", 0, "apid")
		interval = cmd.Flag.Duration("d", rt.Five, "interval")
	)
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i-1] = cmd.Flag.Arg(i)
	}
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}

	ws, err := NewWriter(cmd.Flag.Arg(0), *interval)
	if err != nil {
		return err
	}
	defer func() {
		mr.Close()
		ws.Close()
	}()
	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			if err := ws.WritePacket(p); err != nil {
				return err
			}
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}
