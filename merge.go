package pathtm

import (
  "io/ioutil"
  "os"
  "sort"
  "io"

  "github.com/busoc/rt"
)

func Merge(w io.Writer, files []string) error {
  ix, err := Index()
  if err != nil {
    return err
  }
  defer ix.Close()
  if err := mergeFiles(ix, files); err != nil {
    return err
  }
  if _, err := ix.Seek(0, io.SeekStart); err != nil {
    return err
  }
  _, err = io.CopyBuffer(w, ix, make([]byte, BufferSize))
	return err
}

type Indexer struct {
	inner   *os.File
	packets []rt.Offset
	written int64
}

func Index() (*Indexer, error) {
	w, err := ioutil.TempFile("", "merge_*.dat")
	if err != nil {
		return nil, err
	}
	return &Indexer{inner: w}, nil
}

func (i *Indexer) Write(bs []byte) (int, error) {
	p, err := decodePacket(bs, false)
	if err != nil {
		return 0, err
	}
	o := rt.Offset{
		Sequence: uint(p.Sequence()),
		Pid:      uint(p.Apid()),
		Time:     p.Timestamp(),
		Position: i.written,
		Size:     len(bs),
	}
	n, err := i.inner.Write(bs)
	if err == nil {
		i.packets = append(i.packets, o)
		i.written += int64(n)
	}
	return n, err
}

func (i *Indexer) Read(bs []byte) (int, error) {
	if len(i.packets) == 0 {
		return 0, io.EOF
	}
	o := i.packets[0]
	if _, err := i.inner.Seek(o.Position, io.SeekStart); err != nil {
		return 0, err
	}
	if len(bs) < o.Size {
		return 0, io.ErrShortBuffer
	}
	n, err := i.inner.Read(bs[:o.Size])
	if err == nil {
		i.packets = i.packets[1:]
	}
	return n, err
}

func (i *Indexer) Close() error {
	err := i.inner.Close()
	if e := os.Remove(i.inner.Name()); e != nil {
		err = e
	}
	return err
}

func (x *Indexer) Seek(offset int64, whence int) (int64, error) {
	sort.Slice(x.packets, func(i, j int) bool {
		if x.packets[i].Time.Equal(x.packets[j].Time) {
			if x.packets[i].Pid == x.packets[j].Pid {
				return x.packets[i].Sequence < x.packets[j].Sequence
			}
			return x.packets[i].Pid < x.packets[j].Pid
		}
		return x.packets[i].Time.Before(x.packets[j].Time)
	})
	return x.inner.Seek(offset, whence)
}

func mergeFiles(w io.Writer, files []string) error {
	rs := make([]io.Reader, len(files))
	for i := 0; i < len(files); i++ {
		r, err := os.Open(files[i])
		if err != nil {
			return err
		}
		defer r.Close()
		rs[i] = r
	}
  r := rt.NewReader(io.MultiReader(rs...))
	_, err := io.Copy(w, r)
	return err
}
