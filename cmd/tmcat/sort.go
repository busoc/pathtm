package main

import (
	"os"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
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
	var (
		mode     = cmd.Flag.String("profile", "", "")
		name     = cmd.Flag.String("n", "", "name")
		apid     = cmd.Flag.Int("p", 0, "apid")
		interval = cmd.Flag.Duration("d", rt.Five, "interval")
	)
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	switch *mode {
	case "mem", "memory", "ram":
		defer profile.Start(profile.MemProfile).Stop()
	case "cpu":
		defer profile.Start(profile.CPUProfile).Stop()
	}

	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i-1] = cmd.Flag.Arg(i)
	}
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))

	sort, err := rt.Sort(d, cmd.Flag.Arg(0), *interval)
	if err != nil {
		return err
	} else {
		sort.Pid = *apid
		sort.UPI = *name
	}
	return sort.Sort()
}
