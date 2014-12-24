// Package makwa implements the Makwa password hashing algorithm.
package makwa

import (
	"crypto/hmac"
	"errors"
	"hash"
	"math/big"
)

// Parameters are the aspects of the Makwa algorithm which don't different by
// use.
type Parameters struct {
	HashAlgorithm func() hash.Hash
	Modulus       *big.Int
}

// Hash returns the hash of the given password and salt.
func (p Parameters) Hash(password, salt []byte, cost uint, preHashing bool, postHashingLen uint) ([]byte, error) {
	if preHashing {
		password = p.kdf(password, 64)
	}

	k := p.Modulus.BitLen() / 8
	if k < 160 {
		return nil, errors.New("modulus too short")
	}

	u := len(password)
	if u > 255 || u > (k-32) {
		return nil, errors.New("password too long")
	}

	// sb = KDF(salt || password || BYTE(u), k - 2 - u)
	sb := p.kdf(append(append(salt, password...), byte(u)), uint(k-2-u))

	//xb = BYTE(0x00) || sb || password || BYTE(u)
	xb := append(append(append([]byte{0x00}, sb...), password...), byte(u))

	x := new(big.Int).SetBytes(xb)
	for i := uint(0); i <= cost; i++ {
		x = new(big.Int).Exp(x, two, p.Modulus)
	}

	out := p.pad(x)
	if postHashingLen > 0 {
		out = p.kdf(out, postHashingLen)
	}
	return out, nil
}

var two = big.NewInt(2)

func (p Parameters) pad(x *big.Int) []byte {
	modLen := (p.Modulus.BitLen() + 7) >> 3
	out := x.Bytes()
	if len(out) < modLen {
		out = append(make([]byte, modLen-len(out)), out...)
	}
	return out[:modLen]
}

func (p Parameters) kdf(data []byte, outLen uint) []byte {
	// r = output length of h() in bytes
	r := p.HashAlgorithm().Size()

	// V = BYTE(0x01) || BYTE(0x01) || ... || BYTE(0x01)  # such that len(V) = r
	v := make([]byte, r)
	for i := range v {
		v[i] = 0x01
	}

	// K = BYTE(0x00) || BYTE(0x00) || ... || BYTE(0x00)  # such that len(K) = r
	k := make([]byte, r)

	// K = HMAC(h, K, V || BYTE(0x00) || data)
	k = p.hmac(k, append(append(v, 0x00), data...))

	// V = HMAC(h, K, V)
	v = p.hmac(k, v)

	// K = HMAC(h, K, V || BYTE(0x01) || data)
	k = p.hmac(k, append(append(v, 0x01), data...))

	// V = HMAC(h, K, V)
	v = p.hmac(k, v)

	// T = empty
	var t []byte

	// while len(T) < out_len
	for len(t) < int(outLen) {
		// V = HMAC(h, K, V)
		v = p.hmac(k, v)

		//  T = T || V
		t = append(t, v...)
	}

	// return trunc(T, out_len)
	return t[:outLen]
}

func (p Parameters) hmac(k, v []byte) []byte {
	h := hmac.New(p.HashAlgorithm, k)
	_, _ = h.Write(v)
	return h.Sum(nil)
}
