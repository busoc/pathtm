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

var options = []linewriter.Option{
	linewriter.WithPadding([]byte(" ")),
	linewriter.WithSeparator([]byte("|")),
}

func main() {
	flag.Parse()

	r, err := os.Open(flag.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer r.Close()

	buffer := make([]byte, pathtm.CCSDSHeaderLen)
	line := linewriter.NewWriter(256, options...)
	digest := xxh.New64(0)
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
			line.AppendUint(uint64(i), 4, linewriter.AlignRight)
			line.AppendUint(uint64(c.Apid()), 4, linewriter.AlignRight)
			line.AppendUint(uint64(c.Sequence()), 6, linewriter.AlignRight)
			line.AppendString(c.Segmentation().String(), 12, linewriter.AlignRight)
			line.AppendUint(uint64(c.Len()), 6, linewriter.AlignRight)
			line.AppendBytes(digest.Sum(nil), 16, linewriter.WithZero|linewriter.Hex)

			os.Stdout.Write(append(line.Bytes(), '\n'))
			line.Reset()
		case io.EOF:
			fmt.Fprintf(os.Stdout, "%d packets\n", i)
			return
		default:
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
	}
}
