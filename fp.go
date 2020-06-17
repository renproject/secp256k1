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
	"unsafe"

	"github.com/renproject/surge"
)

// Fp represents an element of the field corresponding to the coordinates of
// the points that lie on the secp256k1 elliptic curve.
type Fp struct {
	inner [5]uint64
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
	x.inner[0] = v & 0xFFFFFFFFFFFFF
	x.inner[1] = v >> 52
	x.inner[2] = 0
	x.inner[3] = 0
	x.inner[4] = 0
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
	x.inner[0] = 0
	x.inner[1] = 0
	x.inner[2] = 0
	x.inner[3] = 0
	x.inner[4] = 0
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

	greater := int(C.secp256k1_fe_set_b32((*C.secp256k1_fe)(unsafe.Pointer(x)), (*C.uchar)(&bs[0]))) == 0
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
	C.secp256k1_fe_get_b32((*C.uchar)(&dst[0]), (*C.secp256k1_fe)(unsafe.Pointer(&x)))
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
	C.secp256k1_fe_add((*C.secp256k1_fe)(unsafe.Pointer(&aCopy)), (*C.secp256k1_fe)(unsafe.Pointer(b)))
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
	C.secp256k1_fe_add((*C.secp256k1_fe)(unsafe.Pointer(x)), (*C.secp256k1_fe)(unsafe.Pointer(a)))
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
	C.secp256k1_fe_negate((*C.secp256k1_fe)(unsafe.Pointer(x)), (*C.secp256k1_fe)(unsafe.Pointer(a)), 0)
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
	C.secp256k1_fe_mul(
		(*C.secp256k1_fe)(unsafe.Pointer(x)),
		(*C.secp256k1_fe)(unsafe.Pointer(a)),
		(*C.secp256k1_fe)(unsafe.Pointer(b)),
	)
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
	C.secp256k1_fe_mul(
		(*C.secp256k1_fe)(unsafe.Pointer(x)),
		(*C.secp256k1_fe)(unsafe.Pointer(a)),
		(*C.secp256k1_fe)(unsafe.Pointer(&bCopy)),
	)
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
	C.secp256k1_fe_sqr((*C.secp256k1_fe)(unsafe.Pointer(x)), (*C.secp256k1_fe)(unsafe.Pointer(a)))
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
	C.secp256k1_fe_inv_var((*C.secp256k1_fe)(unsafe.Pointer(x)), (*C.secp256k1_fe)(unsafe.Pointer(a)))
	x.normalize()
}

// IsZero returns true if the field element is zero and false otherwise.
func (x *Fp) IsZero() bool {
	return (x.inner[0] | x.inner[1] | x.inner[2] | x.inner[3] | x.inner[4]) == 0
}

// IsOne returns true if the field element is zero and false otherwise.
func (x *Fp) IsOne() bool {
	return (x.inner[0] == 1) && ((x.inner[1] | x.inner[2] | x.inner[3] | x.inner[4]) == 0)
}

// IsEven returns true if the field element is even and false otherwise.
func (x *Fp) IsEven() bool {
	return !((x.inner[0] & 1) == 1)
}

// Eq returns true if the two field elements are equal, and false otherwise.
func (x *Fp) Eq(other *Fp) bool {
	return ((x.inner[0] ^ other.inner[0]) |
		(x.inner[1] ^ other.inner[1]) |
		(x.inner[2] ^ other.inner[2]) |
		(x.inner[3] ^ other.inner[3]) |
		(x.inner[4] ^ other.inner[4])) == 0
}

func (x *Fp) normalize() {
	C.secp256k1_fe_normalize_var((*C.secp256k1_fe)(unsafe.Pointer(x)))
}
