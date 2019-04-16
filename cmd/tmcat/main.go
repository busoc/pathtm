package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"time"

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
		Usage: "list [-c csv] [-p apid] <file...>",
		Short: "print packet headers found in file(s)",
		Run:   runList,
	},
	{
		Usage: "diff [-c csv] [-p apid] [-d duration] <file...>",
		Short: "print packet gap(s) found in file(s)",
		Run:   runDiff,
	},
	{
		Usage: "count [-p apid] [-i interval] [-c csv] [-b by] <file...>",
		Short: "count packets found into file(s)",
		Run:   runCount,
	},
	{
		Usage: "sort [-p apid] [-d datadir] <file>",
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

	line := whichLine(*csv)
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

		line.AppendTime(p.Timestamp(), rt.TimeFormat, 0)
		line.AppendTime(p.PTHHeader.Timestamp(), rt.TimeFormat, 0)
		line.AppendUint(uint64(p.Sequence()), 6, linewriter.AlignRight)
		line.AppendString(ft.String(), 16, linewriter.AlignRight)
		line.AppendUint(uint64(p.Apid()), 4, linewriter.AlignRight)
		line.AppendUint(uint64(p.Len()), 6, linewriter.AlignRight)
		line.AppendString(pt.String(), 16, linewriter.AlignRight)
		line.AppendUint(uint64(p.Sid), 8, linewriter.AlignRight)

		os.Stdout.Write(append(line.Bytes(), '\n'))
		line.Reset()
	}
	return nil
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

	line := whichLine(*csv)
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

		os.Stdout.Write(append(line.Bytes(), '\n'))
		line.Reset()
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

	line := whichLine(*csv)
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

				os.Stdout.Write(append(line.Bytes(), '\n'))
				line.Reset()
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
		return key{
			Pid:  p.CCSDSHeader.Apid(),
			When: p.Timestamp().Truncate(d),
		}
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
	sort.Slice(ks, func(i, j int) bool { return ks[i].Pid < ks[j].Pid })
	return ks
}

func whichLine(csv bool) *linewriter.Writer {
	var options []linewriter.Option
	if csv {
		options = append(options, linewriter.AsCSV(true))
	} else {
		options = []linewriter.Option{
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	return linewriter.NewWriter(1024, options...)
}
