package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
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

type MakeFunc func(string, int, time.Time) (string, error)

func runTake(cmd *cli.Command, args []string) error {
	var t taker

	cmd.Flag.StringVar(&t.Prefix, "n", "", "prefix")
	cmd.Flag.StringVar(&t.Format, "f", "", "format")
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
	Datadir  string
	Format   string
	Prefix   string
	Interval time.Duration
	Apid     int
	Size     int
	Count    int
	Current  bool

	Make MakeFunc

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
			return t.moveFile(t.Apid, t.state.Stamp)
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
			if err := t.moveFile(t.Apid, t.state.Stamp); err != nil {
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
	if t.Prefix == "" {
		if t.Apid != 0 {
			t.Prefix = fmt.Sprint(t.Apid)
		} else {
			t.Prefix = "rt"
		}
	} else {
		t.Prefix = strings.TrimRight(t.Prefix, "_-")
	}
	t.Datadir = dir
	var fn roll.NextFunc
	switch t.Format {
	case "":
		fn = rotateFlat(t)
	default:
		make, err := parseSpecifier(t.Format)
		if err != nil {
			return nil, err
		} else {
			t.Make = make
		}
		fn = rotateTime(t)
	}
	return fn, nil
}

func (t *taker) moveFile(apid int, when time.Time) error {
	if t.file == "" {
		return nil
	}
	if t.Current {
		when = time.Now().UTC()
	}
	dir, err := t.Make(t.Datadir, apid, when)
	if err != nil {
		return err
	}
	// dir := filepath.Join(t.Datadir, fmt.Sprintf("%04d", when.Year()))
	// if err := os.MkdirAll(dir, 0755); err != nil {
	// 	return err
	// }
	file := filepath.Join(dir, fmt.Sprintf("%s_%03d.dat", t.Prefix, when.YearDay()))
	if err = copyFile(t.file, file); err == nil {
		err = os.Remove(t.file)
	}
	return err
}

func copyFile(src, dst string) error {
	w, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer w.Close()

	r, err := os.Open(src)
	if err != nil {
		return err
	}
	defer r.Close()

	_, err = io.Copy(w, r)
	return err
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

func rotateFlat(t *taker) roll.NextFunc {
	return func(i int, w time.Time) (io.WriteCloser, []io.Closer, error) {
		if err := os.MkdirAll(t.Datadir, 0755); err != nil {
			return nil, nil, err
		}
		file := fmt.Sprintf("%s_%06d_%s.dat", t.Prefix, i-1, w.Format("20060102_150405"))
		wc, err := os.Create(filepath.Join(t.Datadir, file))
		return wc, nil, err
	}
}

// specifiers for format
// %A: apid
// %Y: year
// %M: month
// %d: day of month
// %D: day of year
// %h: hour
// %m: minute
func parseSpecifier(str string) (MakeFunc, error) {
	isDigit := func(b byte) bool {
		return b >= '0' && b <= '9'
	}
	var funcs []func(int, time.Time) string
	for i := 0; i < len(str); i++ {
		if str[i] != '%' {
			continue
		}
		i++

		var resolution int
		if isDigit(str[i]) {
			pos := i
			for isDigit(str[i]) {
				i++
			}
			x, err := strconv.Atoi(str[pos:i])
			if err != nil {
				return nil, err
			}
			resolution = x
		}

		var f func(int, time.Time) string
		switch str[i] {
		case 'Y':
			f = func(_ int, w time.Time) string { return fmt.Sprintf("%04d", w.Year()) }
		case 'M':
			f = func(_ int, w time.Time) string { return fmt.Sprintf("%02d", w.Month()) }
		case 'd':
			f = func(_ int, w time.Time) string {
				_, _, d := w.Date()
				return fmt.Sprintf("%02d", d)
			}
		case 'D':
			f = func(_ int, w time.Time) string { return fmt.Sprintf("%03d", w.YearDay()) }
		case 'h':
			f = func(_ int, w time.Time) string {
				if resolution > 0 {
					w = w.Truncate(time.Hour * time.Duration(resolution))
				}
				return fmt.Sprintf("%02d", w.Hour())
			}
		case 'm':
			f = func(_ int, w time.Time) string {
				if resolution > 0 {
					w = w.Truncate(time.Minute * time.Duration(resolution))
				}
				return fmt.Sprintf("%02d", w.Minute())
			}
		case 'A':
			f = func(a int, w time.Time) string {
				str := "pathtm"
				if a >= 0 {
					str = strconv.Itoa(a)
				}
				return str
			}
		default:
			return nil, fmt.Errorf("unknown specifier: %s", str[i-1:i+1])
		}
		funcs = append(funcs, f)
	}
	if len(funcs) == 0 {
		return nil, fmt.Errorf("invalid format string: %s", str)
	}
	return func(base string, a int, w time.Time) (string, error) {
		ps := []string{base}
		for _, f := range funcs {
			ps = append(ps, f(a, w))
		}
		dir := filepath.Join(ps...)
		return dir, os.MkdirAll(dir, 0755)
	}, nil
}
