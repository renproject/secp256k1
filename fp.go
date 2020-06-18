package secp256k1

/*

#define USE_FIELD_5X52
#define HAVE___INT128
#define USE_FIELD_INV_BUILTIN
#define USE_NUM_GMP
#define USE_ASM_X86_64

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/src/field.h"
#include "secp256k1/src/field_impl.h"
#include "secp256k1/src/field_5x52_impl.h"

// Included to supress warnings about undefined functions. The two functions
// that are not defined are:
//	secp256k1_num_set_bin
//	secp256k1_num_jacobi
//
// The first function is used in secp256k1_fe_inv_var, but only if
// USE_FIELD_INV_NUM is defined. We instead use define USE_FIELD_INV_BUILTIN.
// It is also used in secp256k1_fe_is_quad_var, which we do not call.
//
// The second function is only used in secp256k1_fe_is_quad_var, which again we
// do not call.
#include "secp256k1/src/num_impl.h"

*/
import "C"
import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"

	"github.com/renproject/surge"
)

// Fp represents an element of the field corresponding to the coordinates of
// the points that lie on the secp256k1 elliptic curve.
type Fp struct {
	inner C.secp256k1_fe
}

// NewFpFromU64 returns a new field element equal to the given unsigned
// integer.
func NewFpFromU64(v uint64) Fp {
	x := Fp{}
	x.SetU64(v)
	return x
}

// SetU64 sets the field element to be equal to the given unsigned integer.
func (x *Fp) SetU64(v uint64) {
	// Don't call out to c here as the implementation is simple enough to
	// warrant avoiding the FFI overhead.

	// Each limb should have no more than 52 nonzero bits when normalized, so
	// we need to put the lower 52 bits of the argument in the first limb, and
	// the higher 12 bits in the second limb.
	x.inner.n[0] = C.uint64_t(v) & 0xFFFFFFFFFFFFF
	x.inner.n[1] = C.uint64_t(v) >> 52
	x.inner.n[2] = 0
	x.inner.n[3] = 0
	x.inner.n[4] = 0
}

// RandomFp returns a random Fp field element.
//
// Panics: This function will panic if there was an error reading bytes from
// the random source.
func RandomFp() Fp {
	x, err := RandomFpNoPanic()
	if err != nil {
		panic(fmt.Sprintf("could not generate random bytes: %v", err))
	}
	return x
}

// RandomFpNoPanic returns a random Fp field element or an error if it could
// not read from the random source.
func RandomFpNoPanic() (Fp, error) {
	var bs [32]byte
	_, err := rand.Read(bs[:])
	if err != nil {
		return Fp{}, err
	}
	x := Fp{}

	// This will reduce the value modulo P, so it does not matter if the bytes
	// represent a number greater than P.
	x.SetB32(bs[:])

	return x, nil
}

// Clear sets the underlying data of the structure to zero. This will leave it
// in a state which is a representation of the zero element.
func (x *Fp) Clear() {
	// Don't call out to c here as the implementation is simple enough to
	// warrant avoiding the FFI overhead.
	x.inner.n[0] = 0
	x.inner.n[1] = 0
	x.inner.n[2] = 0
	x.inner.n[3] = 0
	x.inner.n[4] = 0
}

// Int returns a big.Int representation of the field element.
func (x *Fp) Int() *big.Int {
	ret := new(big.Int)
	x.PutInt(ret)
	return ret
}

// PutInt sets the given big.Int to be equal to the field element.
func (x *Fp) PutInt(dst *big.Int) {
	var bs [32]byte
	x.PutB32(bs[:])
	dst.SetBytes(bs[:])
}

// SetB32 sets the field element to be equal to the given byte slice,
// interepreted as big endian. The field element will be reduced modulo P. This
// function will return true if the bytes represented a number greater than or
// equal to P, and false otherwise.
//
// Panics: If the byte slice has length less than 32, this function will panic.
func (x *Fp) SetB32(bs []byte) bool {
	if len(bs) < 32 {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 32, got %v", len(bs)))
	}

	greater := int(C.secp256k1_fe_set_b32(&x.inner, (*C.uchar)(&bs[0]))) == 0
	if greater {
		x.normalize()
	}

	return greater
}

// PutB32 stores the bytes of the field element into destination in big endian
// form.
//
// Panics: If the byte slice has length less than 32, this function will panic.
func (x Fp) PutB32(dst []byte) {
	if len(dst) < 32 {
		panic(fmt.Sprintf("invalid slice length: length needs to be at least 32, got %v", len(dst)))
	}

	// NOTE: This function assumes that the representation is normalised.
	putB32From5x52(dst, &x.inner.n)
}

// SizeHint implements the surge.SizeHinter interface.
func (x Fp) SizeHint() int { return 32 }

// Marshal implements the surge.Marshaler interface.
func (x Fp) Marshal(w io.Writer, m int) (int, error) {
	if m < 32 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [32]byte
	x.PutB32(bs[:])
	n, err := w.Write(bs[:])

	return m - n, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (x *Fp) Unmarshal(r io.Reader, m int) (int, error) {
	if m < 32 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [32]byte
	n, err := io.ReadFull(r, bs[:])
	m -= n
	if err != nil {
		return m, err
	}
	x.SetB32(bs[:])

	return m, nil
}

// Add computes the addition of the two field elements and stores the result in
// the receiver.
//
// NOTE: This function performs a copy of one of the arguments. To avoid this
// copy, use AddAssign.
func (x *Fp) Add(a, b *Fp) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}
	if b == nil {
		panic("expected second argument to be not be nil")
	}

	x.AddUnsafe(a, b)
}

// AddUnsafe computes the addition of the two field elements and stores the
// result in the receiver.
//
// NOTE: This function performs a copy of one of the arguments. To avoid this
// copy, use AddAssign.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent. If the NULL pointer and the go nil pointer are the
// same, then the function will panic.
func (x *Fp) AddUnsafe(a, b *Fp) {
	aCopy := *a
	C.secp256k1_fe_add(&aCopy.inner, &b.inner)
	*x = aCopy
	x.normalize()
}

// AddAssign computes the addition of the receiver and the argument and stores
// the result in the receiver.
func (x *Fp) AddAssign(a *Fp) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}

	x.AddAssignUnsafe(a)
}

// AddAssignUnsafe computes the addition of the receiver and the argument and
// stores the result in the receiver.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent. If the NULL pointer and the go nil pointer are the
// same, then the function will panic.
func (x *Fp) AddAssignUnsafe(a *Fp) {
	C.secp256k1_fe_add(&x.inner, &a.inner)
	x.normalize()
}

// Negate computes the additive inverse of the field element and stores the
// result in the receiver.
func (x *Fp) Negate(a *Fp) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}

	x.NegateUnsafe(a)
}

// NegateUnsafe computes the additive inverse of the field element and stores
// the result in the receiver.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent. If the NULL pointer and the go nil pointer are the
// same, then the function will panic.
func (x *Fp) NegateUnsafe(a *Fp) {
	// NOTE: The final argument is set to 0 because it is assumed that the
	// representation is normalized.
	C.secp256k1_fe_negate(&x.inner, &a.inner, 0)
	x.normalize()
}

// MulNoAliase computes the product of the two field elements and stores the
// result in the receiver.
//
// NOTE: The second argument, b, must not be aliased by either the receiver or
// the first argument, otherwise the computation will be incorrect.
func (x *Fp) MulNoAliase(a, b *Fp) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}
	if b == nil {
		panic("expected second argument to be not be nil")
	}

	x.MulNoAliaseUnsafe(a, b)
}

// MulNoAliaseUnsafe computes the product of the two field elements and stores
// the result in the receiver.
//
// NOTE: The second argument, b, must not be aliased by either the receiver or
// the first argument, otherwise the computation will be incorrect.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent. If the NULL pointer and the go nil pointer are the
// same, then the function will panic.
func (x *Fp) MulNoAliaseUnsafe(a, b *Fp) {
	// NOTE: The c function defines the pointer to b as restrict, which means
	// that it must not be aliased by x or a.
	C.secp256k1_fe_mul(&x.inner, &a.inner, &b.inner)
	x.normalize()
}

// Mul computes the product of the two field elements and stores the result in
// the receiver.
func (x *Fp) Mul(a, b *Fp) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}
	if b == nil {
		panic("expected second argument to be not be nil")
	}

	x.MulUnsafe(a, b)
}

// MulUnsafe computes the product of the two field elements and stores the
// result in the receiver.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent. If the NULL pointer and the go nil pointer are the
// same, then the function will panic.
func (x *Fp) MulUnsafe(a, b *Fp) {
	// NOTE: The c function defines the pointer to b as restrict, which means
	// that it must not be aliased by x or a. We therefore make a new copy of b
	// to ensure that there is no aliasing.
	bCopy := *b
	C.secp256k1_fe_mul(&x.inner, &a.inner, &bCopy.inner)
	x.normalize()
}

// Sqr computes the square of the field element and stores the result in the
// receiver.
func (x *Fp) Sqr(a *Fp) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}

	x.SqrUnsafe(a)
}

// SqrUnsafe computes the square of the field element and stores the result in
// the receiver.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent. If the NULL pointer and the go nil pointer are the
// same, then the function will panic.
func (x *Fp) SqrUnsafe(a *Fp) {
	C.secp256k1_fe_sqr(&x.inner, &a.inner)
	x.normalize()
}

// Inv computes the multiplicative inverse of the field element and stores the
// result in the receiver.
func (x *Fp) Inv(a *Fp) {
	if a == nil {
		panic("expected first argument to be not be nil")
	}

	x.InvUnsafe(a)
}

// InvUnsafe computes the multiplicative inverse of the field element and
// stores the result in the receiver.
//
// Unsafe: If this function receives nil arguments, the behaviour is
// implementation dependent, because the definition of the NULL pointer in c is
// implementation dependent. If the NULL pointer and the go nil pointer are the
// same, then the function will panic.
func (x *Fp) InvUnsafe(a *Fp) {
	// We use the potentially faster but not constant time version of the
	// inverse function.
	C.secp256k1_fe_inv_var(&x.inner, &a.inner)
	x.normalize()
}

// IsZero returns true if the field element is zero and false otherwise.
func (x *Fp) IsZero() bool {
	return (x.inner.n[0] | x.inner.n[1] | x.inner.n[2] | x.inner.n[3] | x.inner.n[4]) == 0
}

// IsOne returns true if the field element is zero and false otherwise.
func (x *Fp) IsOne() bool {
	return (x.inner.n[0] == 1) && ((x.inner.n[1] | x.inner.n[2] | x.inner.n[3] | x.inner.n[4]) == 0)
}

// IsEven returns true if the field element is even and false otherwise.
func (x *Fp) IsEven() bool {
	return !((x.inner.n[0] & 1) == 1)
}

// Eq returns true if the two field elements are equal, and false otherwise.
func (x *Fp) Eq(other *Fp) bool {
	return ((x.inner.n[0] ^ other.inner.n[0]) |
		(x.inner.n[1] ^ other.inner.n[1]) |
		(x.inner.n[2] ^ other.inner.n[2]) |
		(x.inner.n[3] ^ other.inner.n[3]) |
		(x.inner.n[4] ^ other.inner.n[4])) == 0
}

func (x *Fp) normalize() {
	C.secp256k1_fe_normalize_var(&x.inner)
}

// Writes into the destination byte slice the data from the array of 5 limbs in
// base 52. When using this with the Fp type, it assumes that the data
// representaiton is normalized.
func putB32From5x52(dst []byte, arr *[5]C.uint64_t) {
	dst[0] = byte((arr[4] >> 40) & 0xFF)
	dst[1] = byte((arr[4] >> 32) & 0xFF)
	dst[2] = byte((arr[4] >> 24) & 0xFF)
	dst[3] = byte((arr[4] >> 16) & 0xFF)
	dst[4] = byte((arr[4] >> 8) & 0xFF)
	dst[5] = byte(arr[4] & 0xFF)

	dst[6] = byte((arr[3] >> 44) & 0xFF)
	dst[7] = byte((arr[3] >> 36) & 0xFF)
	dst[8] = byte((arr[3] >> 28) & 0xFF)
	dst[9] = byte((arr[3] >> 20) & 0xFF)
	dst[10] = byte((arr[3] >> 12) & 0xFF)
	dst[11] = byte((arr[3] >> 4) & 0xFF)

	dst[12] = byte(((arr[2] >> 48) & 0xFF) | ((arr[3] & 0xF) << 4))

	dst[13] = byte((arr[2] >> 40) & 0xFF)
	dst[14] = byte((arr[2] >> 32) & 0xFF)
	dst[15] = byte((arr[2] >> 24) & 0xFF)
	dst[16] = byte((arr[2] >> 16) & 0xFF)
	dst[17] = byte((arr[2] >> 8) & 0xFF)
	dst[18] = byte(arr[2] & 0xFF)

	dst[19] = byte((arr[1] >> 44) & 0xFF)
	dst[20] = byte((arr[1] >> 36) & 0xFF)
	dst[21] = byte((arr[1] >> 28) & 0xFF)
	dst[22] = byte((arr[1] >> 20) & 0xFF)
	dst[23] = byte((arr[1] >> 12) & 0xFF)
	dst[24] = byte((arr[1] >> 4) & 0xFF)

	dst[25] = byte(((arr[0] >> 48) & 0xFF) | ((arr[1] & 0xF) << 4))

	dst[26] = byte((arr[0] >> 40) & 0xFF)
	dst[27] = byte((arr[0] >> 32) & 0xFF)
	dst[28] = byte((arr[0] >> 24) & 0xFF)
	dst[29] = byte((arr[0] >> 16) & 0xFF)
	dst[30] = byte((arr[0] >> 8) & 0xFF)
	dst[31] = byte(arr[0] & 0xFF)
}
