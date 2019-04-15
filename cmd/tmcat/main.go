package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"sort"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
)

const helpText = `{{.Name}} scan the HRDP archive to consolidate the USOC HRDP archive

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

var commands = []*cli.Command{
	{
		Usage: "list [-c] [-p] <file...>",
		Short: "",
		Run:   runList,
	},
	{
		Usage: "diff [-p] <file...>",
		Short: "",
		Run:   runDiff,
	},
	{
		Usage: "count <file...>",
		Short: "",
		Run:   runCount,
	},
	{
		Usage: "sort [-p] [-d] <file>",
		Short: "",
		Run:   runSort,
	},
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	log.SetFlags(0)
	if err := cli.Run(commands, cli.Usage("tmcat", helpText, commands), nil); err != nil {
		log.Fatalln(err)
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

	var options []linewriter.Option
	if *csv {
		options = append(options, linewriter.AsCSV(false))
	} else {
		options = []linewriter.Option{
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	line := linewriter.NewWriter(1024, options...)
	for {
		p, err := d.Decode(false)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		ft := p.CCSDSHeader.Segmentation()
		pt := p.ESAHeader.PacketType()

		line.AppendTime(p.ESAHeader.Timestamp(), rt.TimeFormat, 0)
		line.AppendTime(p.PTHHeader.Timestamp(), rt.TimeFormat, 0)
		line.AppendUint(uint64(p.Sequence()), 6, linewriter.AlignRight)
		line.AppendString(ft.String(), 16, linewriter.AlignRight)
		line.AppendUint(uint64(p.Apid()), 4, linewriter.AlignRight)
		line.AppendUint(uint64(p.Length-1), 6, linewriter.AlignRight)
		line.AppendString(pt.String(), 16, linewriter.AlignRight)
		line.AppendUint(uint64(p.Sid), 8, linewriter.Hex|linewriter.WithZero)

		os.Stdout.Write(append(line.Bytes(), '\n'))
		line.Reset()
	}
	return nil
}

type key struct {
	Pid uint16
	Sid uint32
}

func runCount(cmd *cli.Command, args []string) error {
	by := cmd.Flag.String("b", "", "count packets by")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	var byFunc func(pathtm.Packet) key
	switch *by {
	case "", "apid":
		byFunc = byApid
	case "sid", "source":
		byFunc = bySource
	default:
		return fmt.Errorf("invalid value: %s", *by)
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(0))

	stats := make(map[key]rt.Coze)
	seen := make(map[uint16]pathtm.Packet)
	for {
		p, err := d.Decode(false)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		k := byFunc(p)
		cz := stats[k]
		cz.Count++
		cz.Size += uint64(p.CCSDSHeader.Length)
		cz.Last, cz.EndTime = uint64(p.Sequence()), p.ESAHeader.Timestamp()
		if cz.StartTime.IsZero() {
			cz.First, cz.StartTime = cz.Last, cz.EndTime
		}
		if other, ok := seen[p.Apid()]; ok {
			if diff := p.Missing(other); diff > 0 {
				cz.Missing += uint64(diff)
			}
		} else {
		}
		seen[p.Apid()], stats[k] = p, cz
	}
	if len(stats) == 0 {
		return nil
	}
	options := []linewriter.Option{
		linewriter.WithPadding([]byte(" ")),
		linewriter.WithSeparator([]byte("|")),
	}
	line := linewriter.NewWriter(1024, options...)

	ks := keyset(stats)
	for i := 0; i < len(ks); i++ {
		k := ks[i]
		line.AppendUint(uint64(k.Pid), 6, linewriter.AlignLeft)
		if k.Sid > 0 {
			line.AppendUint(uint64(k.Sid), 6, linewriter.AlignLeft)
		}

		cz := stats[k]
		line.AppendUint(cz.Count, 8, linewriter.AlignRight)
		line.AppendUint(cz.Missing, 8, linewriter.AlignRight)
		line.AppendSize(int64(cz.Size), 8, linewriter.AlignRight)
		line.AppendUint(cz.First, 8, linewriter.AlignRight)
		line.AppendTime(cz.StartTime, rt.TimeFormat, linewriter.AlignRight)
		line.AppendUint(cz.Last, 8, linewriter.AlignRight)
		line.AppendTime(cz.EndTime, rt.TimeFormat, linewriter.AlignRight)

		os.Stdout.Write(append(line.Bytes(), '\n'))
		line.Reset()
	}
	return nil
}

func keyset(stats map[key]rt.Coze) []key {
	var ks []key
	for k := range stats {
		ks = append(ks, k)
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].Pid < ks[j].Pid })
	return ks
}

func byApid(p pathtm.Packet) key {
	return key{Pid: p.CCSDSHeader.Apid()}
}

func bySource(p pathtm.Packet) key {
	k := key{
		Pid: p.CCSDSHeader.Apid(),
		Sid: p.ESAHeader.Sid,
	}
	return k
}

func runDiff(cmd *cli.Command, args []string) error {
	apid := cmd.Flag.Int("p", 0, "apid")
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

	options := []linewriter.Option{
		linewriter.WithPadding([]byte(" ")),
		linewriter.WithSeparator([]byte("|")),
	}
	line := linewriter.NewWriter(1024, options...)

	stats := make(map[uint16]pathtm.Packet)
	for {
		p, err := d.Decode(false)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if *apid > 0 && int(p.Apid()) != *apid {
			continue
		}
		if other, ok := stats[p.Apid()]; ok {
			diff := (p.Sequence() - other.Sequence())
			fd, td := other.ESAHeader.Timestamp(), p.ESAHeader.Timestamp()
			if diff != 1 && diff != p.Sequence() && (*duration <= 0 || td.Sub(fd) >= *duration) {
				line.AppendUint(uint64(p.Apid()), 4, 0)
				line.AppendTime(fd, rt.TimeFormat, 0)
				line.AppendTime(td, rt.TimeFormat, 0)
				line.AppendUint(uint64(other.Sequence()), 6, 0)
				line.AppendUint(uint64(p.Sequence()), 6, 0)
				line.AppendUint(uint64(diff-1), 6, linewriter.AlignRight)
				line.AppendDuration(td.Sub(fd), 12, linewriter.AlignRight)

				os.Stdout.Write(append(line.Bytes(), '\n'))
				line.Reset()
			}
		}
		stats[p.Apid()] = p
	}
	return nil
}
