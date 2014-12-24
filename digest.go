package makwa

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
)

// A Digest is a hashed password.
type Digest struct {
	ModulusID   []byte
	Hash        []byte
	Salt        []byte
	WorkFactor  uint
	PreHash     bool
	PostHashLen uint
}

// MarshalText marshals a digest into a text format.
func (d *Digest) MarshalText() ([]byte, error) {
	// BUG(coda): Doesn't elide Base64 padding.

	b := new(bytes.Buffer)

	_, _ = b.WriteString(base64.StdEncoding.EncodeToString(d.ModulusID))
	_, _ = b.WriteRune('_')

	if d.PreHash {
		if d.PostHashLen > 0 {
			_, _ = b.WriteRune('b')
		} else {
			_, _ = b.WriteRune('r')
		}
	} else {
		if d.PostHashLen > 0 {
			_, _ = b.WriteRune('s')
		} else {
			_, _ = b.WriteRune('n')
		}
	}
	man, log := wfMant(uint32(d.WorkFactor))
	_, _ = b.WriteString(fmt.Sprintf(
		"%1d%02d",
		man,
		log,
	))
	_, _ = b.WriteRune('_')

	_, _ = b.WriteString(base64.StdEncoding.EncodeToString(d.Salt))
	_, _ = b.WriteRune('_')

	_, _ = b.WriteString(base64.StdEncoding.EncodeToString(d.Hash))

	return b.Bytes(), nil
}

// UnmarshalText unmarshals a digest from a text format.
func (d *Digest) UnmarshalText(text []byte) error {
	// BUG(coda): Can't unmarshal unpadded Base64.

	parts := bytes.Split(text, []byte{'_'})

	d.ModulusID = make([]byte, len(parts[0]))
	n, err := base64.StdEncoding.Decode(d.ModulusID, parts[0])
	if err != nil {
		return err
	}
	d.ModulusID = d.ModulusID[:n]

	mantissa, err := strconv.Atoi(string(parts[1][1:2]))
	if err != nil {
		return err
	}

	log, err := strconv.Atoi(string(parts[1][2:]))
	if err != nil {
		return err
	}

	d.WorkFactor = 1
	for i := 0; i <= log; i++ {
		d.WorkFactor *= uint(mantissa)
	}

	d.Salt = make([]byte, len(parts[2]))
	n, err = base64.StdEncoding.Decode(d.Salt, append(parts[2], '='))
	d.Salt = d.Salt[:n]

	d.Hash = make([]byte, len(parts[3]))
	n, err = base64.StdEncoding.Decode(d.Hash, append(parts[3], '='))
	d.Hash = d.Hash[:n]

	switch parts[1][0] {
	case 'b':
		d.PreHash = true
		d.PostHashLen = uint(len(d.Hash))
	case 'r':
		d.PreHash = true
		d.PostHashLen = 0
	case 's':
		d.PreHash = false
		d.PostHashLen = uint(len(d.Hash))
	case 'n':
		d.PreHash = false
		d.PostHashLen = 0
	}

	return nil
}
