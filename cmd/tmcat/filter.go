package main

import (
	"io"
	// "os"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
)

func runDispatch(cmd *cli.Command, args []string) error {
	// ccsds := cmd.Flag.Bool("ccsds", false, "only ccsds packet")
	file := cmd.Flag.String("f", "", "file")
	apid := cmd.Flag.Int("p", 0, "apid")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}

	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()

	w, err := os.Create(*file)
	if err != nil {
		return err
	}
	defer w.Close()

	d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(*apid))
	for {
		p, err := d.Decode(true)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

	}
	return nil
}
