package isakmp

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"
)

type DHExchange struct {
	groupID uint16
	prime   *big.Int
	private *big.Int
	size    int
	public  []byte
}

func NewDHExchange(groupID uint16, random io.Reader) (*DHExchange, error) {
	prime, size, err := dhPrime(groupID)
	if err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	rangeSize := new(big.Int).Sub(prime, big.NewInt(3))
	private, err := rand.Int(random, rangeSize)
	if err != nil {
		return nil, fmt.Errorf("%w: DH randomness: %v", ErrInvalidCryptoInput, err)
	}
	private.Add(private, big.NewInt(2))
	public := new(big.Int).Exp(big.NewInt(2), private, prime)
	return &DHExchange{groupID: groupID, prime: prime, private: private, size: size, public: leftPad(public.Bytes(), size)}, nil
}

func (d *DHExchange) Group() uint16  { return d.groupID }
func (d *DHExchange) Public() []byte { return append([]byte(nil), d.public...) }

func (d *DHExchange) SharedSecret(peerPublic []byte) ([]byte, error) {
	if len(peerPublic) != d.size {
		return nil, fmt.Errorf("%w: DH public length %d", ErrInvalidCryptoInput, len(peerPublic))
	}
	peer := new(big.Int).SetBytes(peerPublic)
	upper := new(big.Int).Sub(d.prime, big.NewInt(2))
	if peer.Cmp(big.NewInt(2)) < 0 || peer.Cmp(upper) > 0 {
		return nil, fmt.Errorf("%w: DH public value", ErrInvalidCryptoInput)
	}
	shared := new(big.Int).Exp(peer, d.private, d.prime)
	if shared.Sign() == 0 || shared.Cmp(big.NewInt(1)) == 0 {
		return nil, fmt.Errorf("%w: DH shared secret", ErrInvalidCryptoInput)
	}
	return leftPad(shared.Bytes(), d.size), nil
}

func dhPrime(groupID uint16) (*big.Int, int, error) {
	var value string
	switch groupID {
	case DHGroup2:
		value = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
			"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
			"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
			"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
			"49286651ECE65381FFFFFFFFFFFFFFFF"
	case DHGroup14:
		value = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08" +
			"8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B" +
			"302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9" +
			"A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6" +
			"49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8" +
			"FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C" +
			"180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718" +
			"3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
	default:
		return nil, 0, fmt.Errorf("%w: DH group %d", ErrUnsupportedTransform, groupID)
	}
	prime, ok := new(big.Int).SetString(strings.ReplaceAll(value, " ", ""), 16)
	if !ok {
		panic("invalid embedded MODP prime")
	}
	return prime, (prime.BitLen() + 7) / 8, nil
}

func leftPad(value []byte, size int) []byte {
	out := make([]byte, size)
	copy(out[size-len(value):], value)
	return out
}
