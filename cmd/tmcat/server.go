package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/busoc/pathtm"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
)

func runServer(cmd *cli.Command, args []string) error {
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	if cmd.Flag.NArg() != 2 {
		return fmt.Errorf("not enough arguments")
	}
	if i, err := os.Stat(cmd.Flag.Arg(1)); err != nil || !i.IsDir() {
		return fmt.Errorf("%s should be a directory", cmd.Flag.Arg(1))
	}
	h := HandleList(cmd.Flag.Arg(1))
	http.Handle("/list/", http.StripPrefix("/list/", h))
	return http.ListenAndServe(cmd.Flag.Arg(0), nil)
}

func HandleList(datadir string) http.Handler {
	f := func(w http.ResponseWriter, r *http.Request) {
		dirs := []string{filepath.Join(datadir, r.URL.Path)}
		mr, err := rt.Browse(dirs, true)
		if err != nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		defer mr.Close()

		var apid int
		q := r.URL.Query()
		if pid := q.Get("apid"); pid != "" {
			if i, err := strconv.ParseInt(pid, 10, 64); err == nil {
				apid = int(i)
			} else {
				http.Error(w, "apid parameter: invalid", http.StatusBadRequest)
				return
			}
		}

		d := pathtm.NewDecoder(rt.NewReader(mr), pathtm.WithApid(apid))
		dumpList(d, w, true)
	}
	return http.HandlerFunc(f)
}
