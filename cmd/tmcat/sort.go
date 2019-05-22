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

func runTake(cmd *cli.Command, args []string) error {
	var t taker

	cmd.Flag.DurationVar(&t.Interval, "d", 0, "")
	cmd.Flag.StringVar(&t.Prefix, "n", "", "")
	cmd.Flag.IntVar(&t.Apid, "p", 0, "apid")
	cmd.Flag.IntVar(&t.Size, "s", 0, "size")
	cmd.Flag.IntVar(&t.Count, "c", 0, "count")

	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i-1] = cmd.Flag.Arg(i)
	}

	err := t.Sort(cmd.Flag.Arg(0), dirs)
	if err == nil {
		fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %dKB)\n", t.state.Count, t.state.Skipped, t.state.Size>>10)
	}
	return err
}

type taker struct {
	Interval time.Duration
	Prefix   string
	Apid     int
	Size     int
	Count    int

	state struct {
		Count   int
		Skipped int
		Size    int
		Stamp   time.Time
	}
}

func (t *taker) Sort(file string, dirs []string) error {
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	var wc io.WriteCloser
	if t.Interval > 0 {
		wc, err = roll.Roll(t.Open(file), roll.WithThreshold(t.Size, t.Count))
	} else {
		wc, err = os.Create(file)
	}
	if err != nil {
		return err
	}
	defer wc.Close()

	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(t.Apid))
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			if t.Interval >= rt.Five {
				w := p.Timestamp()
				if !t.state.Stamp.IsZero() && w.Sub(t.state.Stamp) >= t.Interval {
					if r, ok := wc.(*roll.Roller); ok {
						r.Rotate()
					}
				}
				if t.state.Stamp.IsZero() || w.Sub(t.state.Stamp) >= t.Interval {
					t.state.Stamp = w
				}
			}
			if buf, err := p.Marshal(); err == nil {
				if n, err := wc.Write(buf); err != nil {
					t.state.Skipped++
				} else {
					t.state.Size += n
					t.state.Count++
				}
			} else {
				t.state.Skipped++
			}
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}

func (t *taker) Open(dir string) roll.NextFunc {
	if t.Prefix == "" {
		if t.Apid != 0 {
			t.Prefix = fmt.Sprint(t.Apid)
		} else {
			t.Prefix = "rt"
		}
	} else {
		t.Prefix = strings.TrimRight(t.Prefix, "_-")
	}
	return func(i int, w time.Time) (io.WriteCloser, []io.Closer, error) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, nil, err
		}
		file := fmt.Sprintf("%s_%06d_%s.dat", t.Prefix, i-1, w.Format("20060102_150405"))
		wc, err := os.Create(filepath.Join(dir, file))
		return wc, nil, err
	}
}
