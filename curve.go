package abdmecdh

import (
	"errors"
	"math/big"
)

// Weierstrass Curve25519 parameters from BouncyCastle's CustomNamedCurves.
// This is Curve25519 (2^255 - 19) in short Weierstrass form: y^2 = x^3 + Ax + B
var (
	curveP, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	curveA, _ = new(big.Int).SetString("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144", 16)
	curveB, _ = new(big.Int).SetString("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864", 16)
	curveN, _ = new(big.Int).SetString("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED", 16)
	curveGx, _ = new(big.Int).SetString("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD245A", 16)
	curveGy, _ = new(big.Int).SetString("20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9", 16)
)

const (
	fieldSize  = 32 // bytes for a field element
	pointSize  = 65 // 0x04 + 32 bytes X + 32 bytes Y
)

// pointAdd computes (x3, y3) = (x1, y1) + (x2, y2) on the Weierstrass curve.
// Returns (nil, nil) for the point at infinity.
func pointAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	// Handle identity cases
	if x1 == nil && y1 == nil {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2 == nil && y2 == nil {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	// If x1 == x2
	if x1.Cmp(x2) == 0 {
		// If y1 == y2, this is point doubling
		if y1.Cmp(y2) == 0 {
			return pointDouble(x1, y1)
		}
		// Otherwise y1 == -y2, result is point at infinity
		return nil, nil
	}

	p := curveP

	// lambda = (y2 - y1) / (x2 - x1) mod p
	dy := new(big.Int).Sub(y2, y1)
	dx := new(big.Int).Sub(x2, x1)
	dxInv := new(big.Int).ModInverse(dx, p)
	if dxInv == nil {
		return nil, nil
	}
	lambda := new(big.Int).Mul(dy, dxInv)
	lambda.Mod(lambda, p)

	// x3 = lambda^2 - x1 - x2 mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)

	// y3 = lambda * (x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)

	return x3, y3
}

// pointDouble computes (x3, y3) = 2 * (x, y) on the Weierstrass curve.
func pointDouble(x, y *big.Int) (*big.Int, *big.Int) {
	if x == nil && y == nil {
		return nil, nil
	}

	// If y == 0, result is point at infinity
	if y.Sign() == 0 {
		return nil, nil
	}

	p := curveP

	// lambda = (3*x^2 + A) / (2*y) mod p
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, p)
	num := new(big.Int).Mul(big.NewInt(3), x2)
	num.Add(num, curveA)
	num.Mod(num, p)

	den := new(big.Int).Mul(big.NewInt(2), y)
	denInv := new(big.Int).ModInverse(den, p)
	if denInv == nil {
		return nil, nil
	}

	lambda := new(big.Int).Mul(num, denInv)
	lambda.Mod(lambda, p)

	// x3 = lambda^2 - 2*x mod p
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x)
	x3.Sub(x3, x)
	x3.Mod(x3, p)

	// y3 = lambda * (x - x3) - y mod p
	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y)
	y3.Mod(y3, p)

	return x3, y3
}

// scalarMult computes k * (x, y) using double-and-add.
func scalarMult(k *big.Int, x, y *big.Int) (*big.Int, *big.Int) {
	// Reduce k mod N
	k = new(big.Int).Mod(k, curveN)

	var rx, ry *big.Int // point at infinity

	// Copy the point to avoid mutation
	px := new(big.Int).Set(x)
	py := new(big.Int).Set(y)

	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			rx, ry = pointAdd(rx, ry, px, py)
		}
		px, py = pointDouble(px, py)
	}

	return rx, ry
}

// scalarBaseMult computes k * G where G is the generator point.
func scalarBaseMult(k *big.Int) (*big.Int, *big.Int) {
	return scalarMult(k, curveGx, curveGy)
}

// marshalUncompressed serializes an EC point as 0x04 || X (32 bytes) || Y (32 bytes).
func marshalUncompressed(x, y *big.Int) []byte {
	buf := make([]byte, pointSize)
	buf[0] = 0x04
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	// Right-align into 32-byte fields
	copy(buf[1+fieldSize-len(xBytes):1+fieldSize], xBytes)
	copy(buf[1+2*fieldSize-len(yBytes):1+2*fieldSize], yBytes)
	return buf
}

// unmarshalUncompressed parses a 65-byte uncompressed EC point (0x04 || X || Y).
func unmarshalUncompressed(data []byte) (*big.Int, *big.Int, error) {
	if len(data) != pointSize {
		return nil, nil, errors.New("invalid point length: expected 65 bytes")
	}
	if data[0] != 0x04 {
		return nil, nil, errors.New("invalid point prefix: expected 0x04")
	}
	x := new(big.Int).SetBytes(data[1 : 1+fieldSize])
	y := new(big.Int).SetBytes(data[1+fieldSize : 1+2*fieldSize])
	return x, y, nil
}

// isOnCurve checks if (x, y) satisfies y^2 = x^3 + Ax + B (mod P).
func isOnCurve(x, y *big.Int) bool {
	p := curveP

	// y^2 mod p
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, p)

	// x^3 + Ax + B mod p
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Mod(x3, p)

	ax := new(big.Int).Mul(curveA, x)
	ax.Mod(ax, p)

	rhs := new(big.Int).Add(x3, ax)
	rhs.Add(rhs, curveB)
	rhs.Mod(rhs, p)

	return lhs.Cmp(rhs) == 0
}
