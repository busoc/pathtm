package pathtm

func WithApid(apid int) func(CCSDSHeader, ESAHeader) (bool, error) {
	i := uint16(apid)
	return func(c CCSDSHeader, _ ESAHeader) (bool, error) {
		return (i <= 0 || i == c.Apid()), nil
	}
}

func WithSid(sid int) func(CCSDSHeader, ESAHeader) (bool, error) {
	i := uint32(sid)
	return func(_ CCSDSHeader, e ESAHeader) (bool, error) {
		return (i <= 0 || i == e.Sid), nil
	}
}
