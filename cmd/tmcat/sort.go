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
	"github.com/midbel/sizefmt"
	"github.com/pkg/profile"
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

	mode := cmd.Flag.String("profile", "", "")
	suffix := cmd.Flag.Bool("x", false, "")
	cmd.Flag.DurationVar(&t.Interval, "d", 0, "interval")
	cmd.Flag.IntVar(&t.Apid, "p", 0, "apid")
	cmd.Flag.BoolVar(&t.Current, "c", false, "use current time")

	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	switch *mode {
	case "mem", "memory", "ram":
		defer profile.Start(profile.MemProfile).Stop()
	case "cpu":
		defer profile.Start(profile.CPUProfile).Stop()
	}

	var err error

	t.builder, err = rt.NewBuilder(cmd.Flag.Arg(0), *suffix)
	if err != nil {
		return err
	}

	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i-1] = cmd.Flag.Arg(i)
	}
	if err = t.Sort(dirs); err == nil {
		size := sizefmt.Format(float64(t.state.Size), sizefmt.IEC)
		fmt.Fprintf(os.Stdout, "%d packets written (%d skipped, %s)\n", t.state.Count, t.state.Skipped, size)
	}
	return err
}

type taker struct {
	Interval time.Duration
	Apid     int
	Current  bool

	builder rt.Builder

	state struct {
		Count   int
		Skipped int
		Size    int
		Stamp   time.Time
	}

	file    *os.File
	written int
}

func (t *taker) Sort(dirs []string) error {
	if t.Interval == 0 {
		t.Interval = rt.Five
	}
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	if err := t.openFile(); err != nil {
		return err
	}

	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(t.Apid))
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			if err := t.rotateFile(p.Timestamp()); err != nil {
				return err
			}
			buf, err := p.Marshal()
			if err != nil {
				t.state.Skipped++
				continue
			}
			if n, err := t.file.Write(buf); err != nil {
				t.state.Skipped++
			} else {
				t.written += n
				t.state.Size += n
				t.state.Count++
			}
		case io.EOF:
			return t.moveFile(t.state.Stamp)
		default:
			return err
		}
	}
}

func (t *taker) rotateFile(w time.Time) error {
	var err error
	stamp := t.state.Stamp.Truncate(t.Interval)
	if !t.state.Stamp.IsZero() && w.Sub(stamp) >= t.Interval {
		if err = t.moveFile(t.state.Stamp); err != nil {
			return err
		}
		err = t.openFile()
	}
	if t.state.Stamp.IsZero() || w.Sub(stamp) >= t.Interval {
		t.state.Stamp = w
	}
	return err
}

func (t *taker) openFile() error {
	f, err := ioutil.TempFile("", "tmc-tk-*.dat")
	if err == nil {
		t.file = f
	}
	return err
}

func (t *taker) moveFile(when time.Time) error {
	if t.written == 0 {
		return nil
	}
	defer t.file.Close()
	if t.Current {
		when = time.Now().UTC()
	}

	_, err := t.file.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	if err = t.builder.Copy(t.file, t.Apid, when); err == nil {
		t.written = 0
		err = os.Remove(t.file.Name())
	}
	return err
}
