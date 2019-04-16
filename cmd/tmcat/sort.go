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

	c := struct {
		Count   int
		Skipped int
		Size    int
	}{}
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			t := p.Timestamp().Truncate(rt.Five)
			if _, ok := ws[t]; !ok {
				wc, err := createFile(*datadir, t)
				if err != nil {
					return err
				}
				defer wc.Close()
				ws[t] = rt.NewWriter(wc)
			}
			buf, err := p.Marshal()
			if err != nil {
				c.Skipped++
				continue
			}
			if n, err := ws[t].Write(buf); err != nil {
				return err
			} else {
				c.Size += n
				c.Count++
			}
		case io.EOF:
			fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", c.Count, c.Skipped, c.Size>>10)
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

	c := struct {
		Count   int
		Skipped int
		Size    int
	}{}
	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			buf, err := p.Marshal()
			if err != nil {
				c.Skipped++
				continue
			}
			if n, err := w.Write(buf); err != nil {
				c.Skipped++
				continue
			} else {
				c.Size += n
				c.Count++
			}
		case io.EOF:
			fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", c.Count, c.Skipped, c.Size>>10)
			return nil
		default:
			return err
		}
	}
}

func createFile(dir string, t time.Time) (*os.File, error) {
	file, err := rt.Path(dir, t)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}
