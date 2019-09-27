package main

import (
	"fmt"
	"os"

	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
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
		Usage: "list [-c csv] [-p apid] <file...>",
		Short: "print packet headers found in file(s)",
		Run:   runList,
	},
	{
		Usage: "diff [-c csv] [-p apid] [-d duration] <file...>",
		Short: "print packet gap(s) found in file(s)",
		Run:   runDiff,
	},
	{
		Usage: "count [-p apid] [-i interval] [-c csv] [-b by] <file...>",
		Short: "count packets found into file(s)",
		Run:   runCount,
	},
	{
		Usage: "digest <file...>",
		Short: "print CCSDS headers and packet hash",
		Run:   runDigest,
	},
	{
		Usage: "take [-p apid] [-d duration] <pattern> <file...>",
		Short: "gather packets of an apid into its file(s)",
		Run:   runTake,
	},
	{
		Usage: "merge <final> <file...>",
		Short: "merge and reorder packets from multiple files",
		Run:   runMerge,
	},
}

func main() {
	defer func() {
		if err := recover(); err != nil {
			fmt.Fprintf(os.Stderr, "unexpected error: %s\n", err)
		}
	}()
	cli.RunAndExit(commands, cli.Usage("tmcat", helpText, commands))
}

func Line(csv bool) *linewriter.Writer {
	var options []linewriter.Option
	if csv {
		options = append(options, linewriter.AsCSV(true))
	} else {
		options = []linewriter.Option{
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	return linewriter.NewWriter(1024, options...)
}
