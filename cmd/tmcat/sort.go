package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
	"github.com/midbel/roll"
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

type sorter struct {
	Interval time.Duration
	Prefix string
	Apid int
	Size int
	Count int

	state struct {
		Count   int
		Skipped int
		Size    int
		Stamp   time.Time
	}
}

func (s *sorter) Sort(datadir string, dirs []string) error {
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	wc, err := roll.Roll(s.Open(datadir), roll.WithThreshold(s.Size, s.Count))
	if err != nil {
		return err
	}
	defer wc.Close()

	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(s.Apid))
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			if s.Interval >= rt.Five {
				t := p.Timestamp()
				if !s.state.Stamp.IsZero() && t.Sub(s.state.Stamp) >= s.Interval {
					wc.Rotate()
				}
				if s.state.Stamp.IsZero() || t.Sub(s.state.Stamp) >= s.Interval {
					s.state.Stamp = t
				}
			}
			if buf, err := p.Marshal(); err == nil {
				if n, err := wc.Write(buf); err != nil {
					s.state.Skipped++
				} else {
					s.state.Size += n
					s.state.Count++
				}
			} else {
				s.state.Skipped++
			}
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}

func (s *sorter) Open(dir string) roll.NextFunc {
	if s.Prefix == "" {
		if s.Apid != 0 {
			s.Prefix = fmt.Sprint(s.Apid)
		} else {
			s.Prefix = "rt"
		}
	} else {
		s.Prefix = strings.TrimRight(s.Prefix, "_-")
	}
	return func(i int, w time.Time) (io.WriteCloser, []io.Closer, error) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, err
		}
		file := fmt.Sprintf("%s_%06d_%s.dat", s.Prefix, i-1, w.Format("20060102_150405"))
		wc, err := os.Create(filepath.Join(dir, file))
		return wc, nil, err
	}
}

func runSort(cmd *cli.Command, args []string) error {
	var s sorter

	cmd.Flag.DurationVar(&s.Interval, "d", 0, "")
	cmd.Flag.StringVar(&s.Prefix, "n", "", "")
	cmd.Flag.IntVar(&s.Apid, "p", 0, "apid")
	cmd.Flag.IntVar(&s.Size, "s", 0, "size")
	cmd.Flag.IntVar(&s.Count, "c", 0, "count")

	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i-1] = cmd.Flag.Arg(i)
	}

	err := s.Sort(cmd.Flag.Arg(0), dirs)
	if err == nil {
		fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", s.state.Count, s.state.Skipped, s.state.Size>>10)
	}
	return err
}

func createFile(dir string, t time.Time) (*os.File, error) {
	file, err := rt.Path(dir, t)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}
