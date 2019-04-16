package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
)

func runMerge(cmd *cli.Command, args []string) error {
	return cmd.Flag.Parse(args)
}

func runDispatch(cmd *cli.Command, args []string) error {
	datadir := cmd.Flag.String("d", "", "datadir")
	apid := cmd.Flag.Int("p", 0, "apid")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	r, err := os.Open(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer r.Close()

	d := pathtm.NewDecoder(rt.NewReader(r), pathtm.WithApid(*apid))
	ws := make(map[time.Time]io.Writer)

	var skipped, size int
	for i := 1; ; i++ {
		p, err := d.Decode(true)
		switch err {
		case nil:
			t := p.Timestamp().Truncate(rt.Five)
			w, ok := ws[t]
			if !ok {
				file, err := rt.Path(*datadir, t)
				if err != nil {
					skipped++
					i--
					continue
				}
				wc, err := os.Create(file)
				if err != nil {
					return err
				}
				defer wc.Close()
				w = rt.NewWriter(wc)
			}
			buf, err := p.Marshal()
			if err != nil {
				skipped++
				i--
				continue
			}
			if n, err := w.Write(buf); err != nil {
				skipped++
				i--
				continue
			} else {
				size += n
			}
			ws[t] = w
		case io.EOF:
			fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", i-1, skipped, size>>10)
			return nil
		default:
			return err
		}
	}
}

func runSort(cmd *cli.Command, args []string) error {
	datadir := cmd.Flag.String("d", "", "datadir")
	apid := cmd.Flag.Int("p", 0, "apid")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(cmd.Flag.Arg(0)), 0755); err != nil {
		return err
	}

	mr, err := rt.Browse([]string{*datadir}, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	w, err := os.Create(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer w.Close()

	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))

	var skipped, size int
	for i := 1; ; i++ {
		p, err := d.Decode(true)
		switch err {
		case nil:
			buf, err := p.Marshal()
			if err != nil {
				skipped++
				continue
			}
			if n, err := w.Write(buf); err != nil {
				skipped++
				continue
			} else {
				size += n
			}
		case io.EOF:
			fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", i-1, skipped, size>>10)
			return nil
		default:
			return err
		}
	}
}
