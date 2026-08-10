package isakmp

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"testing"
)

func TestMainModeHashesUseRoleSpecificOrdering(t *testing.T) {
	transform := Phase1Transform{Hash: HashSHA1}
	ci, cr := Cookie{1}, Cookie{2}
	hi, err := MainModeHash(transform, []byte("key"), []byte("gi"), []byte("gr"), ci, cr, []byte("sa"), []byte("idi"), true)
	if err != nil {
		t.Fatal(err)
	}
	hr, err := MainModeHash(transform, []byte("key"), []byte("gi"), []byte("gr"), ci, cr, []byte("sa"), []byte("idr"), false)
	if err != nil {
		t.Fatal(err)
	}
	wi, _ := PRF(HashSHA1, []byte("key"), []byte("gi"), []byte("gr"), ci[:], cr[:], []byte("sa"), []byte("idi"))
	wr, _ := PRF(HashSHA1, []byte("key"), []byte("gr"), []byte("gi"), cr[:], ci[:], []byte("sa"), []byte("idr"))
	if !bytes.Equal(hi, wi) || !bytes.Equal(hr, wr) || bytes.Equal(hi, hr) {
		t.Fatal("main mode hash ordering")
	}
}

func TestQuickModeHashes(t *testing.T) {
	transform := Phase1Transform{Hash: HashSHA1}
	key, ni, nr, payloads := []byte("a"), []byte("ni"), []byte("nr"), []byte("payloads")
	messageID := uint32(0x01020304)
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], messageID)
	h1, _ := QuickModeHash1(transform, key, messageID, payloads)
	h2, _ := QuickModeHash2(transform, key, messageID, ni, payloads)
	h3, _ := QuickModeHash3(transform, key, messageID, ni, nr)
	w1, _ := PRF(HashSHA1, key, id[:], payloads)
	w2, _ := PRF(HashSHA1, key, id[:], ni, payloads)
	w3, _ := PRF(HashSHA1, key, []byte{0}, id[:], ni, nr)
	if !bytes.Equal(h1, w1) || !bytes.Equal(h2, w2) || !bytes.Equal(h3, w3) {
		t.Fatal("quick mode hashes")
	}
}

func TestDeriveESPKeyMaterialExpands(t *testing.T) {
	transform := Phase1Transform{Hash: HashSHA1}
	got, err := DeriveESPKeyMaterial(transform, []byte("d"), nil, ProtocolESP, []byte{1, 2, 3, 4}, []byte("ni"), []byte("nr"), 40)
	if err != nil || len(got) != 40 {
		t.Fatalf("len=%d err=%v", len(got), err)
	}
	k1, _ := PRF(HashSHA1, []byte("d"), []byte{ProtocolESP}, []byte{1, 2, 3, 4}, []byte("ni"), []byte("nr"))
	k2, _ := PRF(HashSHA1, []byte("d"), k1, []byte{ProtocolESP}, []byte{1, 2, 3, 4}, []byte("ni"), []byte("nr"))
	want := append(append([]byte(nil), k1...), k2...)
	if !bytes.Equal(got, want) {
		t.Fatalf("keymat=%x", got)
	}
}

func TestPhase2IV(t *testing.T) {
	transform := Phase1Transform{Encryption: EncryptionAESCBC, Hash: HashSHA1}
	got, err := Phase2IV(transform, []byte("last block"), 7)
	if err != nil {
		t.Fatal(err)
	}
	var id [4]byte
	binary.BigEndian.PutUint32(id[:], 7)
	h := sha1.New()
	_, _ = h.Write([]byte("last block"))
	_, _ = h.Write(id[:])
	if !bytes.Equal(got, h.Sum(nil)[:16]) {
		t.Fatalf("iv=%x", got)
	}
}

func TestEncryptedPayloadDecodeAllowsArbitraryPadding(t *testing.T) {
	first, wire, err := MarshalPayloads([]Payload{DataPayload{Kind: PayloadNonce, Data: []byte{1, 2, 3}}})
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := DecodePayloads(first, append(wire, 0, 0))
	if err != nil || len(payloads) != 1 {
		t.Fatalf("payloads=%#v err=%v", payloads, err)
	}
	if payloads, err := DecodePayloads(first, append(wire, 0xa5, 0x01)); err != nil || len(payloads) != 1 {
		t.Fatalf("arbitrary padding rejected: payloads=%#v err=%v", payloads, err)
	}
}
