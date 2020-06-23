package secp256k1

/*

#define USE_NUM_GMP
#define HAVE___INT128

// TODO: What should this be set to?
#define ECMULT_WINDOW_SIZE 24

#include "secp256k1/include/secp256k1.h"

#define USE_SCALAR_4X64
#define USE_SCALAR_INV_BUILTIN

#include "secp256k1/src/util.h"
#include "secp256k1/src/num_gmp_impl.h"
#include "secp256k1/src/scalar.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/scalar_4x64_impl.h"

#define USE_ASM_X86_64
#define USE_FIELD_5X52
#define USE_FIELD_INV_BUILTIN

#include "secp256k1/src/field.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/field_5x52_impl.h"
#include "secp256k1/src/num_impl.h"

#include "secp256k1/src/group.h"
#include "secp256k1/src/group_impl.h"
#include "secp256k1/src/scratch.h"
#include "secp256k1/src/scratch_impl.h"
#include "secp256k1/src/ecmult_const.h"
#include "secp256k1/src/ecmult_const_impl.h"

// NOTE: cgo cannot reference static variables, so we need to redefine the
// generator as a non static variable. The use of the macro is copied from
// group_impl.h.
const secp256k1_ge secp256k1_generator = SECP256K1_GE_CONST(
    0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,
    0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,
    0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,
    0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL
);

// The c null pointer, which we define as it may be different from the go nil
// pointer.
secp256k1_fe * null_ptr = NULL;

*/
import "C"
import (
	"crypto/rand"
	"errors"
	"fmt"
	"unsafe"

	"github.com/renproject/surge"
)

// PointSize is the number of bytes needed to represent a curve point in
// memory.
const PointSize int = int(unsafe.Sizeof(Point{}))

// PointSizeMarshalled is the number of bytes needed to represent a marshalled
// curve point.
const PointSizeMarshalled int = 33

// Point represents a point (group element) on the secp256k1 elliptic curve.
type Point struct {
	inner C.secp256k1_ge
}

// NewPointFromXY constructs a new curve point from the given x and y
// coordinates.
func NewPointFromXY(x, y *Fp) Point {
	p := Point{}
	p.SetXY(x, y)
	return p
}

// NewPointInfinity returns a new curve point that represents the point at
// infinity.
func NewPointInfinity() Point {
	p := Point{}
	p.inner.infinity = 1
	return p
}

// RandomPoint generates a random point on the elliptic curve.
func RandomPoint() Point {
	p := Point{}
	var bs [1]byte
	rand.Read(bs[:])
	b := bs[0] & 1

	for {
		x := RandomFp()
		if C.secp256k1_ge_set_xo_var(&p.inner, &x.inner, C.int(b)) != 0 {
			C.secp256k1_fe_normalize_var(&p.inner.y)
			return p
		}
	}
}

// SetXY sets the curve point to have the given coordinates.
// TODO: Document based on the TODO below.
func (p *Point) SetXY(x, y *Fp) {
	p.inner.infinity = 0
	p.inner.x = x.inner
	p.inner.y = y.inner

	// TODO: Should we check that the point is on the curve?
}

// XY returns the coordinates of the curve point.
func (p *Point) XY() (Fp, Fp) {
	var x, y Fp
	x.inner = p.inner.x
	y.inner = p.inner.y
	return x, y
}

// PutBytes stores the bytes of the field element into destination slice.
//
// Panics: If the byte slice has length less than 33, this function will panic.
func (p *Point) PutBytes(dst []byte) {
	if len(dst) < PointSizeMarshalled {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 33, got %v", len(dst)))
	}

	if p.IsInfinity() {
		dst[0] = 0xFF
	} else {
		dst[0] = byte(p.inner.y.n[0] & 1)
	}

	putB32From5x52(dst[1:PointSizeMarshalled], &p.inner.x)
}

// SetBytes sets the field element to be equal to the given byte slice. It will
// return an error if the data does not represent a valid curve point.
//
// Panics: If the byte slice has length less than 33, this function will panic.
func (p *Point) SetBytes(bs []byte) error {
	if len(bs) < PointSizeMarshalled {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 33, got %v", len(bs)))
	}

	if bs[0] == 0xFF {
		p.inner.infinity = 1
		return nil
	}

	set5x52FromB32(bs[1:PointSizeMarshalled], &p.inner.x)
	if C.secp256k1_ge_set_xo_var(&p.inner, &p.inner.x, C.int(bs[0])&1) == 0 {
		// The x coordinate does not correspond to a valid curve point.
		return errors.New("invalid curve point data")
	}

	// After reconstructing the y coordinate, it is not guaranteed to be
	// normalized, so we do that manually.
	C.secp256k1_fe_normalize_var(&p.inner.y)

	p.inner.infinity = 0

	return nil
}

// SizeHint implements the surge.SizeHinter interface.
func (p Point) SizeHint() int { return PointSizeMarshalled }

// Marshal implements the surge.Marshaler interface.
func (p Point) Marshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < PointSizeMarshalled || rem < PointSizeMarshalled {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	p.PutBytes(buf[:PointSizeMarshalled])

	return buf[PointSizeMarshalled:], rem - PointSizeMarshalled, nil
}

// Unmarshal implements the surge.Unmarshaler interface.
func (p *Point) Unmarshal(buf []byte, rem int) ([]byte, int, error) {
	if len(buf) < PointSizeMarshalled || rem < PointSize {
		return buf, rem, surge.ErrUnexpectedEndOfBuffer
	}

	err := p.SetBytes(buf[:PointSizeMarshalled])
	if err != nil {
		return buf[PointSizeMarshalled:], rem - PointSize, err
	}

	return buf[PointSizeMarshalled:], rem - PointSize, nil
}

// IsInfinity returns true if the point represents the point at infinity, and
// false otherwise.
func (p *Point) IsInfinity() bool {
	return p.inner.infinity != 0
}

// IsOnCurve returns true if the point is on the elliptic curve, and false
// otherwise. The point at infinity will return false.
func (p *Point) IsOnCurve() bool {
	return C.secp256k1_ge_is_valid_var(&p.inner) != 0
}

// Eq returns true if the two curve points are equal, and false otherwise.
func (p *Point) Eq(other *Point) bool {
	if p.IsInfinity() != other.IsInfinity() {
		return false
	}

	if p.IsInfinity() {
		return true
	}

	return fpEq(&p.inner.x, &other.inner.x) && fpEq(&p.inner.y, &other.inner.y)
}

// BaseExp computes the scalar multiplication of the canonical generator of the
// curve by the given scalar.
func (p *Point) BaseExp(scalar *Fn) {
	scalarMul(&p.inner, &C.secp256k1_generator, &scalar.inner)
}

// Scale computes the scalar multiplication of the given curve point by the
// given scalar.
//
//NOTE: It is assumed that the input point is not the point at infinity.
func (p *Point) Scale(a *Point, scalar *Fn) {
	scalarMul(&p.inner, &a.inner, &scalar.inner)
}

// ScaleExt is the same as Scale but also works when the input point represents
// the point at infinity; in this case the result of the scalar multiplication
// will also be the point at infinity.
func (p *Point) ScaleExt(a *Point, scalar *Fn) {
	if a.IsInfinity() {
		p.inner = a.inner
		return
	}

	p.Scale(a, scalar)
}

func scalarMul(dst, a *C.secp256k1_ge, scalar *C.secp256k1_scalar) {
	gej := C.secp256k1_gej{}

	// The final argument should be the maximum bit length of the absolute
	// value of the scalar plus one, hence 256 + 1.
	C.secp256k1_ecmult_const(&gej, a, scalar, 257)
	C.secp256k1_ge_set_gej(dst, &gej)

	// The curve scalar multiplication function doesn't make sure that the
	// coordinates are normalized, so we need to do this manually.
	normalizeXY(dst)
}

// Add computes the curve addition of the two given curve points.
func (p *Point) Add(a, b *Point) {
	pGej, aGej := C.secp256k1_gej{}, C.secp256k1_gej{}
	C.secp256k1_gej_set_ge(&pGej, &p.inner)
	C.secp256k1_gej_set_ge(&aGej, &a.inner)
	C.secp256k1_gej_add_ge_var(&pGej, &aGej, &b.inner, C.null_ptr)
	C.secp256k1_ge_set_gej(&p.inner, &pGej)

	// The curve addition function doesn't make sure that the coordinates are
	// normalized, so we need to do this manually.
	normalizeXY(&p.inner)
}

func normalizeXY(point *C.secp256k1_ge) {
	C.secp256k1_fe_normalize_var(&point.x)
	C.secp256k1_fe_normalize_var(&point.y)
}
