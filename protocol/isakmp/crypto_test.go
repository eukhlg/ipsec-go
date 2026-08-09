package isakmp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"testing"
)

func TestDerivePhase1SecretsPSK(t *testing.T) {
	transform := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA1, AuthMethod: AuthPreSharedKey, DHGroup: DHGroup2, KeyBits: 256}
	psk, ni, nr, shared := []byte("shared key"), []byte("initiator nonce"), []byte("responder nonce"), []byte("DH secret")
	ci, cr := Cookie{1, 2, 3}, Cookie{4, 5, 6}
	got, err := DerivePhase1Secrets(transform, psk, ni, nr, shared, ci, cr)
	if err != nil {
		t.Fatal(err)
	}
	prf := func(key []byte, parts ...[]byte) []byte {
		m := hmac.New(sha1.New, key)
		for _, part := range parts {
			_, _ = m.Write(part)
		}
		return m.Sum(nil)
	}
	wantSKEYID := prf(psk, ni, nr)
	wantD := prf(wantSKEYID, shared, ci[:], cr[:], []byte{0})
	wantA := prf(wantSKEYID, wantD, shared, ci[:], cr[:], []byte{1})
	wantE := prf(wantSKEYID, wantA, shared, ci[:], cr[:], []byte{2})
	if !bytes.Equal(got.SKEYID, wantSKEYID) || !bytes.Equal(got.SKEYIDd, wantD) || !bytes.Equal(got.SKEYIDa, wantA) || !bytes.Equal(got.SKEYIDe, wantE) {
		t.Fatal("RFC 2409 derivation mismatch")
	}
	k1 := prf(wantE, []byte{0})
	k2 := prf(wantE, k1)
	wantKey := append(append([]byte(nil), k1...), k2...)
	if len(got.Key) != 32 || !bytes.Equal(got.Key, wantKey[:32]) {
		t.Fatalf("expanded key=%x", got.Key)
	}
}

func TestPRFRFC2202SHA1Vector(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 20)
	want, _ := hex.DecodeString("b617318655057264e28bc0b6fb378c8ef146be00")
	got, err := PRF(HashSHA1, key, []byte("Hi There"))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("prf=%x err=%v", got, err)
	}
	if !VerifyPRF(HashSHA1, key, want, []byte("Hi There")) || VerifyPRF(HashSHA1, key, append([]byte(nil), want[:19]...), []byte("Hi There")) {
		t.Fatal("PRF verification mismatch")
	}
}

func TestAESCBCKnownAnswerAndRoundTrip(t *testing.T) {
	// NIST SP 800-38A F.2.1, first AES-128 CBC block.
	key, _ := hex.DecodeString("2b7e151628aed2a6abf7158809cf4f3c")
	iv, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	plaintext, _ := hex.DecodeString("6bc1bee22e409f96e93d7e117393172a")
	want, _ := hex.DecodeString("7649abac8119b246cee98e9b12e9197d")
	transform := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA1, KeyBits: 128}
	encryptor, err := NewCBCContext(transform, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	if got := encryptor.Encrypt(plaintext); !bytes.Equal(got, want) {
		t.Fatalf("ciphertext=%x", got)
	}
	decryptor, err := NewCBCContext(transform, key, iv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decryptor.Decrypt(want)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext=%x err=%v", got, err)
	}
}

func TestCBCZeroPaddingAndChainedIV(t *testing.T) {
	transform := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA256, KeyBits: 128}
	key, iv := make([]byte, 16), make([]byte, 16)
	encryptor, _ := NewCBCContext(transform, key, iv)
	first, second := encryptor.Encrypt([]byte("first")), encryptor.Encrypt([]byte("second"))
	decryptor, _ := NewCBCContext(transform, key, iv)
	plainFirst, err := decryptor.Decrypt(first)
	if err != nil || !bytes.Equal(plainFirst[:5], []byte("first")) {
		t.Fatalf("first=%x err=%v", plainFirst, err)
	}
	plainSecond, err := decryptor.Decrypt(second)
	if err != nil || !bytes.Equal(plainSecond[:6], []byte("second")) {
		t.Fatalf("second=%x err=%v", plainSecond, err)
	}
}

func TestInitialPhase1IV(t *testing.T) {
	transform := Phase1Transform{Encryption: Encryption3DESCBC, Hash: HashSHA1, KeyBits: 192}
	got, err := InitialPhase1IV(transform, []byte("gi"), []byte("gr"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha1.Sum([]byte("gigr"))
	if !bytes.Equal(got, digest[:8]) {
		t.Fatalf("iv=%x", got)
	}
}

func TestCBCRejectsInvalidLengths(t *testing.T) {
	transform := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA1, KeyBits: 128}
	if _, err := NewCBCContext(transform, make([]byte, 15), make([]byte, 16)); err == nil {
		t.Fatal("accepted short key")
	}
	context, _ := NewCBCContext(transform, make([]byte, 16), make([]byte, 16))
	if _, err := context.Decrypt([]byte{1}); err == nil {
		t.Fatal("accepted partial block")
	}
}
