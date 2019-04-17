package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
	"github.com/midbel/xxh"
)

func runDigest(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()

	r := bufio.NewReader(rt.NewReader(mr))
	buffer := make([]byte, pathtm.BufferSize)
	line := Line(false)

	seen := make(map[uint16]pathtm.CCSDSHeader)
	for {
		switch _, err := r.Read(buffer); err {
		case nil:
			c, err := pathtm.DecodeCCSDS(buffer[pathtm.PTHHeaderLen:])
			if err != nil {
				return err
			}
			sum := xxh.Sum64(buffer[pathtm.PTHHeaderLen+pathtm.CCSDSHeaderLen:], 0)

			var missing int
			if other, ok := seen[c.Apid()]; ok {
				if diff := c.Missing(other); diff > 0 {
					missing = diff
				}
			}
			seen[c.Apid()] = c

			line.AppendUint(uint64(c.Apid()), 4, linewriter.AlignRight)
			line.AppendUint(uint64(missing), 6, linewriter.AlignRight)
			line.AppendUint(uint64(c.Sequence()), 6, linewriter.AlignRight)
			line.AppendString(c.Segmentation().String(), 12, linewriter.AlignRight)
			line.AppendUint(uint64(c.Len()), 6, linewriter.AlignRight)
			line.AppendUint(sum, 16, linewriter.WithZero|linewriter.Hex)

			os.Stdout.Write(append(line.Bytes(), '\n'))
			line.Reset()
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}

func runList(cmd *cli.Command, args []string) error {
	apid := cmd.Flag.Int("p", 0, "apid")
	csv := cmd.Flag.Bool("c", false, "csv format")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))

	line := Line(*csv)
	for {

		switch p, err := d.Decode(false); err {
		case nil:
			ft := p.CCSDSHeader.Segmentation()
			pt := p.ESAHeader.PacketType()

			line.AppendTime(p.Timestamp(), rt.TimeFormat, 0)
			line.AppendTime(p.PTHHeader.Timestamp(), rt.TimeFormat, 0)
			line.AppendUint(uint64(p.Sequence()), 6, linewriter.AlignRight)
			line.AppendString(ft.String(), 16, linewriter.AlignRight)
			line.AppendUint(uint64(p.Apid()), 4, linewriter.AlignRight)
			line.AppendUint(uint64(p.Len()), 6, linewriter.AlignRight)
			line.AppendString(pt.String(), 16, linewriter.AlignRight)
			line.AppendUint(uint64(p.Sid), 8, linewriter.AlignRight)

			io.Copy(os.Stdout, line)
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}

func runCount(cmd *cli.Command, args []string) error {
	apid := cmd.Flag.Int("p", 0, "count packets only by apid")
	interval := cmd.Flag.Duration("i", 0, "count packets within interval")
	csv := cmd.Flag.Bool("c", false, "csv")
	by := cmd.Flag.String("b", "", "count packets by")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var groupby KeyFunc
	switch *by {
	case "", "apid":
		groupby = byApid(*interval)
	case "sid", "source":
		groupby = bySource(*interval)
	default:
		return fmt.Errorf("invalid value: %s", *by)
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))

	line := Line(*csv)
	stats, err := countPackets(d, groupby)
	if err != nil {
		return err
	}
	for i, ks := 0, keyset(stats); i < len(ks); i++ {
		k := ks[i]
		line.AppendUint(uint64(k.Pid), 6, linewriter.AlignLeft)
		if k.Sid > 0 {
			line.AppendUint(uint64(k.Sid), 6, linewriter.AlignLeft)
		}

		cz := stats[k]
		line.AppendUint(cz.Count, 8, linewriter.AlignRight)
		if *by == "" || *by == "apid" {
			line.AppendUint(cz.Missing, 8, linewriter.AlignRight)
		}
		line.AppendSize(int64(cz.Size), 8, linewriter.AlignRight)
		line.AppendUint(cz.First, 8, linewriter.AlignRight)
		line.AppendTime(cz.StartTime, rt.TimeFormat, linewriter.AlignRight)
		line.AppendUint(cz.Last, 8, linewriter.AlignRight)
		line.AppendTime(cz.EndTime, rt.TimeFormat, linewriter.AlignRight)

		io.Copy(os.Stdout, line)
	}
	return nil
}

func runDiff(cmd *cli.Command, args []string) error {
	apid := cmd.Flag.Int("p", 0, "apid")
	csv := cmd.Flag.Bool("c", false, "csv")
	duration := cmd.Flag.Duration("d", 0, "minimum gap duration")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))

	line := Line(*csv)
	stats := make(map[uint16]pathtm.Packet)
	for {
		p, err := d.Decode(false)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if other, ok := stats[p.Apid()]; ok {
			fd, td := other.Timestamp(), p.Timestamp()
			if diff := p.Missing(other); diff > 0 && (*duration <= 0 || td.Sub(fd) >= *duration) {
				line.AppendUint(uint64(p.Apid()), 4, linewriter.AlignRight)
				line.AppendTime(fd, rt.TimeFormat, linewriter.AlignRight)
				line.AppendTime(td, rt.TimeFormat, linewriter.AlignRight)
				line.AppendUint(uint64(other.Sequence()), 6, linewriter.AlignRight)
				line.AppendUint(uint64(p.Sequence()), 6, linewriter.AlignRight)
				line.AppendUint(uint64(diff), 6, linewriter.AlignRight)
				line.AppendDuration(td.Sub(fd), 12, linewriter.AlignRight)

				io.Copy(os.Stdout, line)
			}
		}
		stats[p.Apid()] = p
	}
	return nil
}

type key struct {
	Pid  uint16
	Sid  uint32
	When time.Time
}

type KeyFunc func(pathtm.Packet) key

func byApid(d time.Duration) KeyFunc {
	f := func(p pathtm.Packet) key {
		k := key{
			Pid: p.CCSDSHeader.Apid(),
		}
		if d >= rt.Five {
			k.When = p.Timestamp().Truncate(d)
		}
		return k
	}
	return f
}

func bySource(d time.Duration) KeyFunc {
	by := byApid(d)
	f := func(p pathtm.Packet) key {
		k := by(p)
		k.Sid = p.ESAHeader.Sid
		return k
	}
	return f
}

func countPackets(d *pathtm.Decoder, groupby KeyFunc) (map[key]rt.Coze, error) {
	stats := make(map[key]rt.Coze)
	seen := make(map[uint16]pathtm.Packet)

	for {
		p, err := d.Decode(false)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		k := groupby(p)
		cz := stats[k]
		cz.Count++
		cz.Size += uint64(p.CCSDSHeader.Length)

		cz.Last, cz.EndTime = uint64(p.Sequence()), p.Timestamp()
		if cz.StartTime.IsZero() {
			cz.First, cz.StartTime = cz.Last, cz.EndTime
		}

		if other, ok := seen[p.Apid()]; ok {
			if diff := p.Missing(other); diff > 0 {
				cz.Missing += uint64(diff)
			}
		}
		seen[p.Apid()], stats[k] = p, cz
	}
	return stats, nil
}

func keyset(stats map[key]rt.Coze) []key {
	var ks []key
	for k := range stats {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool {
		if ks[i].Pid == ks[j].Pid {
			return ks[i].When.Before(ks[j].When)
		}
		return ks[i].Pid < ks[j].Pid
	})
	return ks
}
