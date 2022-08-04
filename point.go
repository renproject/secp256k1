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
	inner C.secp256k1_gej
}

// NewPointFromXY constructs a new curve point from the given x and y
// coordinates.
func NewPointFromXY(x, y *Fp) (Point, error) {
	p := Point{}
	p.SetXY(x, y)
	if !p.IsOnCurve() {
		return Point{}, errors.New("given coordinates do not correspond to a valid curve point")
	}
	return p, nil
}

// NewPointInfinity returns a new curve point that represents the point at
// infinity.
func NewPointInfinity() Point {
	p := Point{}
	p.inner.infinity = 1
	return p
}

// RandomPoint generates a random point on the elliptic curve.
//
// Panics: This function will panic if there was an error reading bytes from
// the random source.
func RandomPoint() Point {
	p, err := RandomPointNoPanic()
	if err != nil {
		panic(fmt.Sprintf("could not generate random bytes: %v", err))
	}
	return p
}

// RandomPointNoPanic generates a random point on the elliptic curve.
func RandomPointNoPanic() (Point, error) {
	var p Point
	var tmp C.secp256k1_ge
	var bs [1]byte

	_, err := rand.Read(bs[:])
	if err != nil {
		return Point{}, err
	}

	b := bs[0] & 1
	for {
		x := RandomFp()
		if C.secp256k1_ge_set_xo_var(&tmp, &x.inner, C.int(b)) != 0 {
			C.secp256k1_fe_normalize_var(&tmp.y)
			C.secp256k1_gej_set_ge(&p.inner, &tmp)
			return p, nil
		}
	}
}

// SetXY sets the curve point to have the given coordinates. Does not check if
// the point is actaully on the curve.
func (p *Point) SetXY(x, y *Fp) {
	p.inner.infinity = 0
	p.inner.x = x.inner
	p.inner.y = y.inner

	// Set z = 1.
	p.inner.z.n[0] = 1
	p.inner.z.n[1] = 0
	p.inner.z.n[2] = 0
	p.inner.z.n[3] = 0
	p.inner.z.n[4] = 0
}

// XY returns the coordinates of the curve point, or an error if it is the
// point at infinity (which does not have valid x and y coordinates).
func (p *Point) XY() (Fp, Fp, error) {
	if p.IsInfinity() {
		return Fp{}, Fp{}, errors.New("point at infinity does not have valid cartesian coordinates")
	}
	var x, y Fp
	var tmp C.secp256k1_ge

	C.secp256k1_ge_set_gej(&tmp, &p.inner)
	// Even though after the previous call `p` will represent the same curve
	// point, the representation changes and can cause the x or y coordinates
	// to be unnormalised. We therefore normalise the point which will also
	// ensure that the returned xy coordinates are also normalised.
	normalizeXYZ(&p.inner)
	x.inner = tmp.x
	y.inner = tmp.y
	x.normalize()
	y.normalize()
	return x, y, nil
}

// PutBytes stores the bytes of the field element into destination slice.
//
// Panics: If the byte slice has length less than 33, this function will panic.
func (p *Point) PutBytes(dst []byte) {
	if len(dst) < PointSizeMarshalled {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 33, got %v", len(dst)))
	}

	var tmp C.secp256k1_ge
	pCopy := *p
	C.secp256k1_ge_set_gej(&tmp, &pCopy.inner)
	C.secp256k1_fe_normalize_var(&tmp.x)
	C.secp256k1_fe_normalize_var(&tmp.y)

	if pCopy.IsInfinity() {
		dst[0] = 0xFF
	} else {
		dst[0] = byte(tmp.y.n[0] & 1)
	}

	putB32From5x52(dst[1:PointSizeMarshalled], &tmp.x)
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

	var tmp C.secp256k1_ge

	set5x52FromB32(bs[1:PointSizeMarshalled], &tmp.x)
	if C.secp256k1_ge_set_xo_var(&tmp, &tmp.x, C.int(bs[0])&1) == 0 {
		// The x coordinate does not correspond to a valid curve point.
		C.secp256k1_gej_clear(&p.inner)
		return errors.New("invalid curve point data")
	}

	// After reconstructing the y coordinate, it is not guaranteed to be
	// normalized, so we do that manually.
	C.secp256k1_fe_normalize_var(&tmp.y)

	C.secp256k1_gej_set_ge(&p.inner, &tmp)

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
	var tmp C.secp256k1_ge
	C.secp256k1_ge_set_gej(&tmp, &p.inner)
	return C.secp256k1_ge_is_valid_var(&tmp) != 0
}

// HasEvenY returns true if the y coordinate of the curve point is even.
func (p *Point) HasEvenY() bool {
	var tmp C.secp256k1_ge
	C.secp256k1_ge_set_gej(&tmp, &p.inner)
	C.secp256k1_fe_normalize_var(&tmp.y)

	return C.secp256k1_fe_is_odd(&tmp.y) == 0
}

// Eq returns true if the two curve points are equal, and false otherwise.
func (p *Point) Eq(other *Point) bool {
	if p.IsInfinity() != other.IsInfinity() {
		return false
	}

	if p.IsInfinity() {
		return true
	}

	pCopy := *p
	otherCopy := *other

	// Scale p so that the z fields are equal. Once the z fields are equal, the
	// points will be equal if and only if the x and y fields are equal.
	var s C.secp256k1_fe
	C.secp256k1_fe_inv(&s, &pCopy.inner.z)
	C.secp256k1_fe_mul(&s, &s, &otherCopy.inner.z)
	C.secp256k1_gej_rescale(&pCopy.inner, &s)

	normalizeXYZ(&pCopy.inner)
	normalizeXYZ(&otherCopy.inner)

	return fpEq(&pCopy.inner.x, &otherCopy.inner.x) && fpEq(&pCopy.inner.y, &otherCopy.inner.y)
}

// BaseExp computes the scalar multiplication of the canonical generator of the
// curve by the given scalar.
func (p *Point) BaseExp(scalar *Fn) {
	if scalar == nil {
		panic("expected first argument to not be nil")
	}

	p.BaseExpUnsafe(scalar)
}

// BaseExpUnsafe computes the scalar multiplication of the canonical generator
// of the curve by the given scalar.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent.
func (p *Point) BaseExpUnsafe(scalar *Fn) {
	scalarMul(&p.inner, &C.secp256k1_generator, &scalar.inner)
}

// Scale computes the scalar multiplication of the given curve point by the
// given scalar.
//
//NOTE: It is assumed that the input point is not the point at infinity.
func (p *Point) Scale(a *Point, scalar *Fn) {
	if a == nil {
		panic("expected first argument to not be nil")
	}
	if scalar == nil {
		panic("expected second argument to not be nil")
	}

	p.ScaleUnsafe(a, scalar)
}

// ScaleUnsafe computes the scalar multiplication of the given curve point by
// the given scalar.
//
//NOTE: It is assumed that the input point is not the point at infinity.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent.
func (p *Point) ScaleUnsafe(a *Point, scalar *Fn) {
	var tmp C.secp256k1_ge
	C.secp256k1_ge_set_gej(&tmp, &a.inner)
	scalarMul(&p.inner, &tmp, &scalar.inner)
}

// ScaleExt is the same as Scale but also works when the input point represents
// the point at infinity; in this case the result of the scalar multiplication
// will also be the point at infinity.
func (p *Point) ScaleExt(a *Point, scalar *Fn) {
	if a == nil {
		panic("expected first argument to not be nil")
	}
	if scalar == nil {
		panic("expected second argument to not be nil")
	}

	p.ScaleExtUnsafe(a, scalar)
}

// ScaleExtUnsafe is the same as Scale but also works when the input point
// represents the point at infinity; in this case the result of the scalar
// multiplication will also be the point at infinity.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent.
func (p *Point) ScaleExtUnsafe(a *Point, scalar *Fn) {
	if a.IsInfinity() {
		p.inner = a.inner
		return
	}

	p.ScaleUnsafe(a, scalar)
}

func scalarMul(dst *C.secp256k1_gej, a *C.secp256k1_ge, scalar *C.secp256k1_scalar) {
	// The final argument should be the maximum bit length of the absolute
	// value of the scalar plus one, hence 256 + 1.
	C.secp256k1_ecmult_const(dst, a, scalar, 257)

	// The curve scalar multiplication function doesn't make sure that the
	// coordinates are normalized, so we need to do this manually.
	normalizeXYZ(dst)
}

// Add computes the curve addition of the two given curve points.
func (p *Point) Add(a, b *Point) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}
	if b == nil {
		panic("expected second argument to be not be nil")
	}

	p.AddUnsafe(a, b)
}

// AddUnsafe computes the curve addition of the two given curve points.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent.
func (p *Point) AddUnsafe(a, b *Point) {
	C.secp256k1_gej_add_var(&p.inner, &a.inner, &b.inner, C.null_ptr)

	// The curve addition function doesn't make sure that the coordinates are
	// normalized, so we need to do this manually.
	normalizeXYZ(&p.inner)
}

// Negate computes the negation of the given curve point.
func (p *Point) Negate(a *Point) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}

	p.NegateUnsafe(a)
}

// NegateUnsafe computes the negation of given curve points.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent.
func (p *Point) NegateUnsafe(a *Point) {
	C.secp256k1_gej_neg(&p.inner, &a.inner)

	// The curve addition function doesn't make sure that the coordinates are
	// normalized, so we need to do this manually.
	normalizeXYZ(&p.inner)
}

func normalizeXYZ(point *C.secp256k1_gej) {
	C.secp256k1_fe_normalize_var(&point.x)
	C.secp256k1_fe_normalize_var(&point.y)
	C.secp256k1_fe_normalize_var(&point.z)
}
