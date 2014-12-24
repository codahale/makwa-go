// Package makwa implements the Makwa password hashing algorithm.
//
// Makwa is a candidate in the Password Hashing Competition which uses squaring
// modulo Blum integers to provide a one-way function with number-theoretic
// security.
//
// https://password-hashing.net/submissions/specs/Makwa-v0.pdf
package makwa

import (
	"bytes"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math/big"
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
	n, err = base64.StdEncoding.Decode(d.Salt, parts[2])
	d.Salt = d.Salt[:n]

	d.Hash = make([]byte, len(parts[3]))
	n, err = base64.StdEncoding.Decode(d.Hash, parts[3])
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

// ErrBadPassword is returned when a bad password is provided.
var ErrBadPassword = errors.New("bad password")

// CheckPassword safely compares a password to a digest of a password.
func CheckPassword(
	modulus *big.Int,
	alg func() hash.Hash,
	digest *Digest,
	password []byte,
) error {
	d, err := Hash(
		password,
		digest.Salt,
		modulus,
		alg,
		digest.WorkFactor,
		digest.PreHash,
		digest.PostHashLen,
	)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(digest.Hash, d.Hash) != 1 {
		return ErrBadPassword
	}
	return nil
}

// Hash returns a digest of the given password using the given parameters.
func Hash(
	password, salt []byte,
	modulus *big.Int,
	alg func() hash.Hash,
	workFactor uint,
	preHash bool,
	postHashLen uint,
) (*Digest, error) {
	if preHash {
		password = kdf(alg, password, 64)
	}

	k := modulus.BitLen() / 8
	if k < 160 {
		return nil, errors.New("modulus too short")
	}

	u := len(password)
	if u > 255 || u > (k-32) {
		return nil, errors.New("password too long")
	}

	modulusID := kdf(alg, modulus.Bytes(), 8)

	// sb = KDF(salt || password || BYTE(u), k - 2 - u)
	sb := kdf(alg, append(append(salt, password...), byte(u)), uint(k-2-u))

	//xb = BYTE(0x00) || sb || password || BYTE(u)
	xb := append(append(append([]byte{0x00}, sb...), password...), byte(u))

	x := new(big.Int).SetBytes(xb)
	for i := uint(0); i <= workFactor; i++ {
		x = new(big.Int).Exp(x, two, modulus)
	}

	out := pad(modulus, x)
	if postHashLen > 0 {
		out = kdf(alg, out, postHashLen)
	}

	return &Digest{
		ModulusID:   modulusID,
		Hash:        out,
		Salt:        salt,
		WorkFactor:  workFactor,
		PreHash:     preHash,
		PostHashLen: postHashLen,
	}, nil
}

var two = big.NewInt(2)

func pad(modulus, x *big.Int) []byte {
	modLen := (modulus.BitLen() + 7) >> 3
	out := x.Bytes()
	if len(out) < modLen {
		out = append(make([]byte, modLen-len(out)), out...)
	}
	return out[:modLen]
}

func kdf(alg func() hash.Hash, data []byte, outLen uint) []byte {
	// r = output length of h() in bytes
	r := alg().Size()

	// V = BYTE(0x01) || BYTE(0x01) || ... || BYTE(0x01)  # such that len(V) = r
	v := make([]byte, r)
	for i := range v {
		v[i] = 0x01
	}

	// K = BYTE(0x00) || BYTE(0x00) || ... || BYTE(0x00)  # such that len(K) = r
	k := make([]byte, r)

	// K = HMAC(h, K, V || BYTE(0x00) || data)
	k = mac(alg, k, append(append(v, 0x00), data...))

	// V = HMAC(h, K, V)
	v = mac(alg, k, v)

	// K = HMAC(h, K, V || BYTE(0x01) || data)
	k = mac(alg, k, append(append(v, 0x01), data...))

	// V = HMAC(h, K, V)
	v = mac(alg, k, v)

	// T = empty
	var t []byte

	// while len(T) < out_len
	for len(t) < int(outLen) {
		// V = HMAC(h, K, V)
		v = mac(alg, k, v)

		//  T = T || V
		t = append(t, v...)
	}

	// return trunc(T, out_len)
	return t[:outLen]
}

func mac(alg func() hash.Hash, k, v []byte) []byte {
	h := hmac.New(alg, k)
	_, _ = h.Write(v)
	return h.Sum(nil)
}

func wfMant(wf uint32) (mant, log uint32) {
	j := uint32(0)
	for wf > 3 && (wf&1) == 0 {
		wf = (wf >> 1) | (wf << 31)
		j++
	}

	if !(wf == 2 || wf == 3) {
		panic("invalid work factor")
	}

	return wf, j
}
