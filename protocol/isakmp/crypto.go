package isakmp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
)

var ErrInvalidCryptoInput = errors.New("isakmp: invalid crypto input")

type Phase1Secrets struct {
	SKEYID  []byte
	SKEYIDd []byte
	SKEYIDa []byte
	SKEYIDe []byte
	Key     []byte
}

// PRF computes the IKEv1 negotiated HMAC pseudo-random function.
func PRF(hashAlgorithm uint16, key []byte, parts ...[]byte) ([]byte, error) {
	transform := Phase1Transform{Hash: hashAlgorithm}
	hashFunc, err := transform.hashFunc()
	if err != nil {
		return nil, err
	}
	mac := hmac.New(hashFunc, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil), nil
}

// VerifyPRF compares an IKE hash without leaking a data-dependent prefix.
func VerifyPRF(hashAlgorithm uint16, key, expected []byte, parts ...[]byte) bool {
	actual, err := PRF(hashAlgorithm, key, parts...)
	return err == nil && len(actual) == len(expected) && subtle.ConstantTimeCompare(actual, expected) == 1
}

// DerivePhase1Secrets implements the RFC 2409 pre-shared-key derivation.
func DerivePhase1Secrets(transform Phase1Transform, preSharedKey, initiatorNonce, responderNonce, sharedSecret []byte, initiatorCookie, responderCookie Cookie) (Phase1Secrets, error) {
	if len(preSharedKey) == 0 || len(initiatorNonce) == 0 || len(responderNonce) == 0 || len(sharedSecret) == 0 {
		return Phase1Secrets{}, ErrInvalidCryptoInput
	}
	hashFunc, err := transform.hashFunc()
	if err != nil {
		return Phase1Secrets{}, err
	}
	prf := func(key []byte, parts ...[]byte) []byte {
		mac := hmac.New(hashFunc, key)
		for _, part := range parts {
			_, _ = mac.Write(part)
		}
		return mac.Sum(nil)
	}
	skeyid := prf(preSharedKey, initiatorNonce, responderNonce)
	zero, one, two := []byte{0}, []byte{1}, []byte{2}
	skeyidd := prf(skeyid, sharedSecret, initiatorCookie[:], responderCookie[:], zero)
	skeyida := prf(skeyid, skeyidd, sharedSecret, initiatorCookie[:], responderCookie[:], one)
	skeyide := prf(skeyid, skeyida, sharedSecret, initiatorCookie[:], responderCookie[:], two)
	key, err := expandKey(hashFunc, skeyide, transform.KeyBits/8)
	if err != nil {
		return Phase1Secrets{}, err
	}
	return Phase1Secrets{SKEYID: skeyid, SKEYIDd: skeyidd, SKEYIDa: skeyida, SKEYIDe: skeyide, Key: key}, nil
}

func expandKey(hashFunc func() hash.Hash, seed []byte, size int) ([]byte, error) {
	if len(seed) == 0 || size <= 0 {
		return nil, ErrInvalidCryptoInput
	}
	if len(seed) >= size {
		return append([]byte(nil), seed[:size]...), nil
	}
	out, previous := make([]byte, 0, size), []byte{0}
	for len(out) < size {
		mac := hmac.New(hashFunc, seed)
		_, _ = mac.Write(previous)
		previous = mac.Sum(nil)
		out = append(out, previous...)
	}
	return out[:size], nil
}

// InitialPhase1IV returns the leftmost cipher-block-sized bytes of
// HASH(g^xi | g^xr), as specified by RFC 2409 Appendix B.
func InitialPhase1IV(transform Phase1Transform, initiatorPublic, responderPublic []byte) ([]byte, error) {
	hashFunc, err := transform.hashFunc()
	if err != nil {
		return nil, err
	}
	blockSize, err := transform.blockSize()
	if err != nil {
		return nil, err
	}
	h := hashFunc()
	_, _ = h.Write(initiatorPublic)
	_, _ = h.Write(responderPublic)
	digest := h.Sum(nil)
	if len(digest) < blockSize {
		return nil, ErrInvalidCryptoInput
	}
	return append([]byte(nil), digest[:blockSize]...), nil
}

type CBCContext struct {
	block cipher.Block
	iv    []byte
}

func (c *CBCContext) CurrentIV() []byte { return append([]byte(nil), c.iv...) }

func NewCBCContext(transform Phase1Transform, key, iv []byte) (*CBCContext, error) {
	var block cipher.Block
	var err error
	switch transform.Encryption {
	case EncryptionAESCBC:
		block, err = aes.NewCipher(key)
	case Encryption3DESCBC:
		block, err = des.NewTripleDESCipher(key)
	default:
		return nil, fmt.Errorf("%w: encryption %d", ErrUnsupportedTransform, transform.Encryption)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCryptoInput, err)
	}
	if len(iv) != block.BlockSize() {
		return nil, fmt.Errorf("%w: IV length %d", ErrInvalidCryptoInput, len(iv))
	}
	return &CBCContext{block: block, iv: append([]byte(nil), iv...)}, nil
}

// Encrypt zero-pads to the next block boundary and advances the chained IV.
func (c *CBCContext) Encrypt(plaintext []byte) []byte {
	size := len(plaintext)
	if remainder := size % c.block.BlockSize(); remainder != 0 {
		size += c.block.BlockSize() - remainder
	}
	out := make([]byte, size)
	copy(out, plaintext)
	if len(out) != 0 {
		cipher.NewCBCEncrypter(c.block, c.iv).CryptBlocks(out, out)
		copy(c.iv, out[len(out)-c.block.BlockSize():])
	}
	return out
}

// Decrypt retains RFC 2409 zero padding because payload lengths determine
// where meaningful plaintext ends. It advances the chained IV.
func (c *CBCContext) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 || len(ciphertext)%c.block.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: ciphertext length %d", ErrInvalidCryptoInput, len(ciphertext))
	}
	nextIV := append([]byte(nil), ciphertext[len(ciphertext)-c.block.BlockSize():]...)
	out := append([]byte(nil), ciphertext...)
	cipher.NewCBCDecrypter(c.block, c.iv).CryptBlocks(out, out)
	copy(c.iv, nextIV)
	return out, nil
}

func (t Phase1Transform) blockSize() (int, error) {
	switch t.Encryption {
	case EncryptionAESCBC:
		return aes.BlockSize, nil
	case Encryption3DESCBC:
		return des.BlockSize, nil
	default:
		return 0, fmt.Errorf("%w: encryption %d", ErrUnsupportedTransform, t.Encryption)
	}
}
