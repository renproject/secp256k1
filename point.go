package secp256k1

/*

#define USE_NUM_GMP
#define USE_FIELD_5X52

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/src/group.h"

*/
import "C"

// Point represents a point (group element) on the secp256k1 elliptic curve.
type Point struct {
	inner C.secp256k1_ge
}

func (p *Point) PutBytes(dst []byte) {
	// putB32From5x52(dst[0:32], &p.inner.x.n)
	// putB32From5x52(dst[32:64], &p.inner.x.n)
	dst[64] = byte(p.inner.infinity)
}

// IsInfinity returns true if the point represents the point at infinity, and
// false otherwise.
func (p *Point) IsInfinity() bool {
	return p.inner.infinity != 0
}
