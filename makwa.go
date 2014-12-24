// Package makwa implements the Makwa password hashing algorithm.
package makwa

import (
	"crypto/hmac"
	"errors"
	"hash"
	"math/big"
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
