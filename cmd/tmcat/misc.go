package main

import (
	"bufio"
	"io"
	"os"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
	"github.com/midbel/xxh"
)

func runDigest(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()

	r := bufio.NewReader(rt.NewReader(mr))
	buffer := make([]byte, pathtm.BufferSize)
	line := Line(false)

	seen := make(map[uint16]pathtm.CCSDSHeader)
	for {
		switch _, err := r.Read(buffer); err {
		case nil:
			c, err := pathtm.DecodeCCSDS(buffer[pathtm.PTHHeaderLen:])
			if err != nil {
				return err
			}
			sum := xxh.Sum64(buffer[pathtm.PTHHeaderLen+pathtm.CCSDSHeaderLen:], 0)

			var missing int
			if other, ok := seen[c.Apid()]; ok {
				if diff := c.Missing(other); diff > 0 {
					missing = diff
				}
			}
			seen[c.Apid()] = c

			line.AppendUint(uint64(c.Apid()), 4, linewriter.AlignRight)
			line.AppendUint(uint64(missing), 6, linewriter.AlignRight)
			line.AppendUint(uint64(c.Sequence()), 6, linewriter.AlignRight)
			line.AppendString(c.Segmentation().String(), 12, linewriter.AlignRight)
			line.AppendUint(uint64(c.Len()), 6, linewriter.AlignRight)
			line.AppendUint(sum, 16, linewriter.WithZero|linewriter.Hex)

			os.Stdout.Write(append(line.Bytes(), '\n'))
			line.Reset()
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}
