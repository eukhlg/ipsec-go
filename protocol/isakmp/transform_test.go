package isakmp

import (
	"errors"
	"testing"
)

func phase1Transform(encryption, hash, group, keyBits uint16) Transform {
	attributes := []Attribute{
		TVAttribute(AttributeP1Encryption, encryption),
		TVAttribute(AttributeP1Hash, hash),
		TVAttribute(AttributeP1AuthMethod, AuthPreSharedKey),
		TVAttribute(AttributeP1DHGroup, group),
	}
	if keyBits != 0 {
		attributes = append(attributes, TVAttribute(AttributeP1KeyLength, keyBits))
	}
	return Transform{Number: 1, ID: TransformIKE, Attributes: attributes}
}

func TestParsePhase1Transform(t *testing.T) {
	tests := []struct {
		name string
		wire Transform
		bits int
	}{
		{"aes-default", phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 0), 128},
		{"aes-256", phase1Transform(EncryptionAESCBC, HashSHA256, DHGroup14, 256), 256},
		{"3des", phase1Transform(Encryption3DESCBC, HashSHA1, DHGroup2, 0), 192},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParsePhase1Transform(test.wire)
			if err != nil || got.KeyBits != test.bits {
				t.Fatalf("suite=%#v err=%v", got, err)
			}
		})
	}
}

func TestParsePhase1TransformRejectsUnsafeOrAmbiguousOffers(t *testing.T) {
	tests := []Transform{
		phase1Transform(EncryptionDESCBC, HashSHA1, DHGroup2, 0),
		phase1Transform(EncryptionAESCBC, HashMD5, DHGroup2, 128),
		phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup1, 128),
		phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 64),
	}
	duplicate := phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 128)
	duplicate.Attributes = append(duplicate.Attributes, TVAttribute(AttributeP1Hash, HashSHA1))
	for _, transform := range append(tests, duplicate) {
		_, err := ParsePhase1Transform(transform)
		if err == nil || (!errors.Is(err, ErrUnsupportedTransform) && !errors.Is(err, ErrInvalidPayload)) {
			t.Fatalf("expected transform rejection, got %v", err)
		}
	}
}

func TestParsePhase1TransformAcceptsTLVInteger(t *testing.T) {
	transform := phase1Transform(EncryptionAESCBC, HashSHA1, DHGroup2, 0)
	transform.Attributes = append(transform.Attributes, TLVAttribute(AttributeP1KeyLength, []byte{1, 0}))
	suite, err := ParsePhase1Transform(transform)
	if err != nil || suite.KeyBits != 256 {
		t.Fatalf("suite=%#v err=%v", suite, err)
	}
}

func TestParseESPTransform(t *testing.T) {
	transform := Transform{Number: 1, ID: TransformESPAES, Attributes: []Attribute{
		TVAttribute(AttributeP2Encapsulation, EncapsulationTransport),
		TVAttribute(AttributeP2Authentication, ESPAuthHMACSHA196),
		TVAttribute(AttributeP2KeyLength, 256),
	}}
	suite, err := ParseESPTransform(transform)
	if err != nil || suite.KeyBits != 256 || suite.Encapsulation != EncapsulationTransport {
		t.Fatalf("suite=%#v err=%v", suite, err)
	}
}

func TestParseESPTransformRejectsTunnelAndMissingAESKeyLength(t *testing.T) {
	for _, transform := range []Transform{
		{Number: 1, ID: TransformESPAES, Attributes: []Attribute{
			TVAttribute(AttributeP2Encapsulation, EncapsulationTunnel),
			TVAttribute(AttributeP2Authentication, ESPAuthHMACSHA196),
			TVAttribute(AttributeP2KeyLength, 128),
		}},
		{Number: 1, ID: TransformESPAES, Attributes: []Attribute{
			TVAttribute(AttributeP2Encapsulation, EncapsulationTransport),
			TVAttribute(AttributeP2Authentication, ESPAuthHMACSHA196),
		}},
	} {
		if _, err := ParseESPTransform(transform); !errors.Is(err, ErrUnsupportedTransform) {
			t.Fatalf("expected unsupported transform, got %v", err)
		}
	}
}
