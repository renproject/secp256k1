package testutil

import (
	"crypto/rand"
	"errors"
)

type errReader struct{}

func (r errReader) Read(b []byte) (int, error) {
	return 0, errors.New("read error")
}

// UseErrReader calls the given function with crypto/rand.Reader being set to a
// reader that always returns an error. After the function call, the
// crypto/rand.Reader is left unchanged.
func UseErrReader(f func()) {
	hold := rand.Reader
	defer func() { rand.Reader = hold }()

	rand.Reader = errReader{}
	f()
}
