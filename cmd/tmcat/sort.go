package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
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

	cmd.Flag.DurationVar(&t.Interval, "d", 0, "interval")
	cmd.Flag.IntVar(&t.Apid, "p", 0, "apid")
	cmd.Flag.IntVar(&t.Size, "s", 0, "size")
	cmd.Flag.IntVar(&t.Count, "c", 0, "count")
	cmd.Flag.BoolVar(&t.Current, "x", false, "use current time")

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
	Apid     int
	Size     int
	Count    int
	Current  bool

	builder rt.Builder

	state struct {
		Count   int
		Skipped int
		Size    int
		Stamp   time.Time
	}
	file string
}

func (t *taker) Sort(file string, dirs []string) error {
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	var wc io.WriteCloser
	if t.Interval > 0 {
		fn, err := t.Open(file)
		if err != nil {
			return err
		}
		wc, err = roll.Roll(fn, roll.WithThreshold(t.Size, t.Count))
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
			if err := t.rotateAndMove(wc, p.Timestamp()); err != nil {
				return err
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
			return t.moveFile(t.state.Stamp)
		default:
			return err
		}
	}
}

func (t *taker) rotateAndMove(wc io.Writer, w time.Time) error {
	if t.Interval < rt.Five {
		return nil
	}
	if !t.state.Stamp.IsZero() && w.Sub(t.state.Stamp) >= t.Interval {
		if r, ok := wc.(*roll.Roller); ok {
			r.Rotate()
			if err := t.moveFile(t.state.Stamp); err != nil {
				return err
			}
		}
	}
	if t.state.Stamp.IsZero() || w.Sub(t.state.Stamp) >= t.Interval {
		t.state.Stamp = w
	}
	return nil
}

func (t *taker) Open(dir string) (roll.NextFunc, error) {
	b, err := rt.NewBuilder(dir)
	if err != nil {
		return nil, err
	}
	t.builder = b
	return rotateTime(t), nil
}

func (t *taker) moveFile(when time.Time) error {
	if t.file == "" {
		return nil
	}
	if t.Current {
		when = time.Now().UTC()
	}

	r, err := os.Open(t.file)
	if err != nil {
		return err
	}
	defer r.Close()
	return t.builder.Copy(r, t.Apid, when)
}

func rotateTime(t *taker) roll.NextFunc {
	return func(_ int, _ time.Time) (io.WriteCloser, []io.Closer, error) {
		wc, err := ioutil.TempFile("", "tmc-tk-*.dat")
		if err == nil {
			t.file = wc.Name()
		} else {
			t.file = ""
		}
		return wc, nil, err
	}
}
