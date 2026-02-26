package abdmecdh

import (
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
)

// OIDs for EC public key encoding
var (
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidPrimeField  = asn1.ObjectIdentifier{1, 2, 840, 10045, 1, 1}
)

// ECParameters matches BouncyCastle's explicit EC parameter encoding
// ECParameters ::= SEQUENCE {
//   version INTEGER,
//   fieldID SEQUENCE { fieldType OID, prime INTEGER },
//   curve SEQUENCE { a OCTET STRING, b OCTET STRING },
//   base OCTET STRING,
//   order INTEGER,
//   cofactor INTEGER
// }
type ecParameters struct {
	Version int
	FieldID fieldID
	Curve   curveCoeffs
	Base    []byte
	Order   *big.Int
	Cofactor int
}

type fieldID struct {
	FieldType asn1.ObjectIdentifier
	Prime     *big.Int
}

type curveCoeffs struct {
	A []byte
	B []byte
}

// subjectPublicKeyInfo matches X.509 SubjectPublicKeyInfo
type subjectPublicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

// marshalX509PublicKey produces a DER-encoded SubjectPublicKeyInfo matching
// BouncyCastle's output for Weierstrass Curve25519 with explicit parameters.
func marshalX509PublicKey(x, y *big.Int) ([]byte, error) {
	point := marshalUncompressed(x, y)
	generator := marshalUncompressed(curveGx, curveGy)

	// Pad A and B to exactly 32 bytes
	aBytes := padToFieldSize(curveA.Bytes())
	bBytes := padToFieldSize(curveB.Bytes())

	params := ecParameters{
		Version: 1,
		FieldID: fieldID{
			FieldType: oidPrimeField,
			Prime:     curveP,
		},
		Curve: curveCoeffs{
			A: aBytes,
			B: bBytes,
		},
		Base:     generator,
		Order:    curveN,
		Cofactor: 8,
	}

	paramsBytes, err := asn1.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal EC parameters: %w", err)
	}

	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidECPublicKey,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		PublicKey: asn1.BitString{
			Bytes:     point,
			BitLength: len(point) * 8,
		},
	}

	return asn1.Marshal(spki)
}

// padToFieldSize pads a byte slice to exactly fieldSize (32) bytes.
func padToFieldSize(b []byte) []byte {
	if len(b) >= fieldSize {
		return b[len(b)-fieldSize:]
	}
	padded := make([]byte, fieldSize)
	copy(padded[fieldSize-len(b):], b)
	return padded
}

// marshalX509PublicKeyBase64 is a convenience wrapper.
func marshalX509PublicKeyBase64(x, y *big.Int) (string, error) {
	der, err := marshalX509PublicKey(x, y)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
