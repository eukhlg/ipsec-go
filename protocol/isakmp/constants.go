// Package isakmp implements strict ISAKMP and IKEv1 packet codecs.
package isakmp

type PayloadType uint8

const (
	PayloadNone           PayloadType = 0
	PayloadSA             PayloadType = 1
	PayloadProposal       PayloadType = 2
	PayloadTransform      PayloadType = 3
	PayloadKeyExchange    PayloadType = 4
	PayloadIdentification PayloadType = 5
	PayloadCertificate    PayloadType = 6
	PayloadCertificateReq PayloadType = 7
	PayloadHash           PayloadType = 8
	PayloadSignature      PayloadType = 9
	PayloadNonce          PayloadType = 10
	PayloadNotification   PayloadType = 11
	PayloadDelete         PayloadType = 12
	PayloadVendorID       PayloadType = 13
	PayloadNATOADraft     PayloadType = 16
	PayloadNATD           PayloadType = 20
	PayloadNATOA          PayloadType = 21
	PayloadNATDDraft      PayloadType = 130
	PayloadNATOADraftAlt  PayloadType = 131
)

const (
	NotifyResponderLifetime uint16 = 24576
	NotifyInitialContact    uint16 = 24578
	NotifyRThere            uint16 = 36136
	NotifyRThereACK         uint16 = 36137
)

const (
	LifeTypeSeconds   uint16 = 1
	LifeTypeKilobytes uint16 = 2
)

type ExchangeType uint8

const (
	ExchangeBase            ExchangeType = 1
	ExchangeIdentityProtect ExchangeType = 2
	ExchangeAuthentication  ExchangeType = 3
	ExchangeAggressive      ExchangeType = 4
	ExchangeInformational   ExchangeType = 5
	ExchangeQuickMode       ExchangeType = 32
	ExchangeNewGroup        ExchangeType = 33
)

type Flags uint8

const (
	FlagEncrypted Flags = 1 << iota
	FlagCommit
	FlagAuthenticationOnly
)

const (
	VersionIKEv1          = 0x10
	DOIIPsec              = 1
	SituationIdentityOnly = 1
)

const (
	ProtocolIKE uint8 = 1
	ProtocolAH  uint8 = 2
	ProtocolESP uint8 = 3
)

const (
	TransformIKE     uint8 = 1
	TransformESPDES  uint8 = 2
	TransformESP3DES uint8 = 3
	TransformESPAES  uint8 = 12
)

const (
	AttributeP1Encryption uint16 = 1
	AttributeP1Hash       uint16 = 2
	AttributeP1AuthMethod uint16 = 3
	AttributeP1DHGroup    uint16 = 4
	AttributeP1LifeType   uint16 = 11
	AttributeP1LifeValue  uint16 = 12
	AttributeP1KeyLength  uint16 = 14
)

const (
	AttributeP2LifeType       uint16 = 1
	AttributeP2LifeValue      uint16 = 2
	AttributeP2DHGroup        uint16 = 3
	AttributeP2Encapsulation  uint16 = 4
	AttributeP2Authentication uint16 = 5
	AttributeP2KeyLength      uint16 = 6
)

const (
	EncryptionDESCBC           uint16 = 1
	Encryption3DESCBC          uint16 = 5
	EncryptionAESCBC           uint16 = 7
	HashMD5                    uint16 = 1
	HashSHA1                   uint16 = 2
	HashSHA256                 uint16 = 4
	AuthPreSharedKey           uint16 = 1
	AuthRSASignature           uint16 = 3
	DHGroup1                   uint16 = 1
	DHGroup2                   uint16 = 2
	DHGroup5                   uint16 = 5
	DHGroup14                  uint16 = 14
	ESPAuthHMACMD596           uint16 = 1
	ESPAuthHMACSHA196          uint16 = 2
	EncapsulationTunnel        uint16 = 1
	EncapsulationTransport     uint16 = 2
	EncapsulationNATTTransport uint16 = 4
)

const (
	IDIPv4Address uint8 = 1
	IDFQDN        uint8 = 2
	IDUserFQDN    uint8 = 3
	IDIPv4Subnet  uint8 = 4
)
