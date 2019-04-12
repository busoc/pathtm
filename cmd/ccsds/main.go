package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/busoc/pathtm"
	"github.com/midbel/linewriter"
	"github.com/midbel/xxh"
)

func main() {
	flag.Parse()

	r, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer r.Close()

	buffer := make([]byte, pathtm.CCSDSHeaderLen)
	digest := xxh.New64(0)

  d := Dump()
	for i := 1; ; i++ {
		_, err := r.Read(buffer)
		switch err {
		case nil:
			digest.Reset()

			c, err := pathtm.DecodeCCSDS(buffer)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(3)
			}
			if _, err := io.CopyN(digest, r, int64(c.Length)); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(2)
			}
      d.Dump(c, digest.Sum64())
		case io.EOF:
			fmt.Fprintf(os.Stdout, "%d packets\n", i)
			return
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}

type Dumper struct {
  line *linewriter.Writer
  seen map[uint16]pathtm.CCSDSHeader
}

func Dump() *Dumper {
  options := []linewriter.Option{
  	linewriter.WithPadding([]byte(" ")),
  	linewriter.WithSeparator([]byte("|")),
  }
  d := Dumper{
    line: linewriter.NewWriter(256, options...),
    seen: make(map[uint16]pathtm.CCSDSHeader),
  }
  return &d
}

func (d *Dumper) Dump(c pathtm.CCSDSHeader, digest uint64) {
  defer d.line.Reset()

  var missing uint16
  if other, ok := d.seen[c.Apid()]; ok {
    diff := c.Sequence() - other.Sequence()
    if diff != c.Sequence() && diff > 1 {
      missing = diff-1
    }
  }
  d.seen[c.Apid()] = c

  d.line.AppendUint(uint64(c.Apid()), 4, linewriter.AlignRight)
  d.line.AppendUint(uint64(missing), 6, linewriter.AlignRight)
  d.line.AppendUint(uint64(c.Sequence()), 6, linewriter.AlignRight)
  d.line.AppendString(c.Segmentation().String(), 12, linewriter.AlignRight)
  d.line.AppendUint(uint64(c.Len()), 6, linewriter.AlignRight)
  d.line.AppendUint(digest, 16, linewriter.WithZero|linewriter.Hex)

  os.Stdout.Write(append(d.line.Bytes(), '\n'))
}
