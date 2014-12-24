package makwa

import (
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"math/big"
)

// PublicParameters are the public parameters associated with Makwa.
type PublicParameters struct {
	N    *big.Int
	Hash func() hash.Hash
}

// ModulusID returns a fingerprint of the modulus.
func (p PublicParameters) ModulusID() []byte {
	return kdf(p.Hash, p.N.Bytes(), 8)
}

// PrivateParameters are the private parameters associated with Makwa.
type PrivateParameters struct {
	PublicParameters
	P, Q *big.Int
}

// GenerateParameters generates a random Makwa modulus of the given size.
func GenerateParameters(bits int) (*PrivateParameters, error) {
	pBits := (bits + 1) >> 1
	qBits := bits - pBits

	p, err := rand.Prime(rand.Reader, pBits)
	if err != nil {
		return nil, err
	}

	q, err := rand.Prime(rand.Reader, qBits)
	if err != nil {
		return nil, err
	}

	return &PrivateParameters{
		PublicParameters: PublicParameters{
			N:    new(big.Int).Mul(p, q),
			Hash: sha256.New,
		},
		P: p,
		Q: q,
	}, nil
}
