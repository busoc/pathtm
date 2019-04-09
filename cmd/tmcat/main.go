package main

import (
  "log"
  "io"
  "os"

  "github.com/midbel/linewriter"
  "github.com/midbel/cli"
  "github.com/busoc/rt"
  "github.com/busoc/pathtm"
)

const helpText = `{{.Name}} scan the HRDP archive to consolidate the USOC HRDP archive

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

var commands = []*cli.Command{
	{
		Usage: "list [-c] <file...>",
		Short: "",
		Run:   runList,
	},
	{
		Usage: "diff <file...>",
		Short: "",
		Run:   runDiff,
	},
	{
		Usage: "count <file...>",
		Short: "",
		Run:   runCount,
	},
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	log.SetFlags(0)
	if err := cli.Run(commands, cli.Usage("tmcat", helpText, commands), nil); err != nil {
		log.Fatalln(err)
	}
}

func runList(cmd *cli.Command, args []string) error {
  csv := cmd.Flag.Bool("c", false, "csv format")
  if err := cmd.Flag.Parse(args); err != nil {
    return err
  }
  mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
  d := pathtm.NewDecoder(rt.NewReader(mr))

  var options []func(*linewriter.Writer)
	if *csv {
		options = append(options, linewriter.AsCSV(false))
	} else {
		options = []func(*linewriter.Writer){
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	line := linewriter.NewWriter(1024, options...)
	for {
    p, err := d.Decode(false)
    if err != nil {
      if err == io.EOF {
        break
      }
      return err
    }

    ft := p.CCSDSHeader.Segmentation()
    pt := p.ESAHeader.PacketType()

    line.AppendTime(p.ESAHeader.Timestamp(), rt.TimeFormat, 0)
    line.AppendTime(p.PTHHeader.Timestamp(), rt.TimeFormat, 0)
    line.AppendUint(uint64(p.CCSDSHeader.Sequence()), 6, linewriter.AlignRight)
    line.AppendString(ft.String(), 16, linewriter.AlignRight)
    line.AppendUint(uint64(p.CCSDSHeader.Apid()), 4, linewriter.AlignRight)
    line.AppendUint(uint64(p.CCSDSHeader.Length-1), 6, linewriter.AlignRight)
    line.AppendString(pt.String(), 16, linewriter.AlignRight)
    os.Stdout.Write(append(line.Bytes(), '\n'))

    line.Reset()
  }
  return nil
}

func runCount(cmd *cli.Command, args []string) error {
  return cmd.Flag.Parse(args)
}

func runDiff(cmd *cli.Command, args []string) error {
  return cmd.Flag.Parse(args)
}
