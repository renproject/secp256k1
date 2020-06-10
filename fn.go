package secp256k1

/*

// NOTE: Requires the gmp c library.
#define USE_NUM_GMP

#define HAVE___INT128
#define USE_SCALAR_4X64
#define USE_SCALAR_INV_BUILTIN

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/src/util.h"
#include "secp256k1/src/num_gmp_impl.h"
#include "secp256k1/src/scalar.h"
#include "secp256k1/src/scalar_impl.h"
#include "secp256k1/src/scalar_4x64_impl.h"

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

// Fn represents an element of the field defined by the prime N, where N is the
// order of the elliptic curve group secp256k1.
type Fn struct {
	inner C.secp256k1_scalar
}

// NewFnFromUint returns a new field element equal to the given unsigned
// integer.
func NewFnFromUint(v uint16) Fn {
	x := Fn{}
	x.SetUint(v)
	return x
}

// RandomFn returns a random field element.
//
// Panics: This function will panic if there was an error reading bytes from
// the random source.
func RandomFn() Fn {
	x, err := RandomFnSafe()
	if err != nil {
		panic(fmt.Sprintf("could not generate random bytes: %v", err))
	}
	return x
}

// RandomFnSafe returns a random field element or an error.
func RandomFnSafe() (Fn, error) {
	var bs [32]byte
	_, err := rand.Read(bs[:])
	if err != nil {
		return Fn{}, err
	}
	x := Fn{}

	// This will reduce the value modulo N, so it does not matter if the bytes
	// represent a number greater than N.
	x.SetB32(bs[:])
	return x, nil
}

// Clear sets the underlying data of the structure to zero. This will leave it
// in a state which is a representation of the zero element.
func (x *Fn) Clear() {
	C.secp256k1_scalar_clear(&x.inner)
}

// Int returns a big.Int representation of the field element.
func (x *Fn) Int() *big.Int {
	ret := new(big.Int)
	x.GetInt(ret)
	return ret
}

// GetInt sets the given big.Int to be equal to the field element.
func (x *Fn) GetInt(dst *big.Int) {
	var bs [32]byte
	x.GetB32(bs[:])
	dst.SetBytes(bs[:])
}

// SetB32 sets the field element to be equal to the given byte slice,
// interepreted as big endian. The field element will be reduced modulo N. The
// argument `overflow` will be non zero if the bytes represented a number
// greater than or equal to N, and zero otherwise.
//
// Panics: If the byte slice has length less than 32, this function will panic.
func (x *Fn) SetB32(bs []byte) bool {
	// 64 bits in case the c representation of an int has 64 bits.
	var overflow int64

	C.secp256k1_scalar_set_b32(
		&x.inner,
		(*C.uchar)(&bs[0]),
		(*C.int)(unsafe.Pointer(&overflow)),
	)
	return overflow != 0
}

// SetB32SecKey sets the receiver from the given byte slice, intepreted in big
// endian form, and returns a bool indicating whether the bytes represent a
// valid private key. The bytes don't represent a valid private key if either
// they represent a number greater than or equal to N, or if they represent the
// zero element.
//
// Panics: If the byte slice has length less than 32, this function will panic.
func (x *Fn) SetB32SecKey(bs []byte) bool {
	return int(C.secp256k1_scalar_set_b32_seckey(&x.inner, (*C.uchar)(C.CBytes(bs)))) == 1
}

// GetB32 stores the bytes of the field element into destination in big endian
// form.
func (x Fn) GetB32(dst []byte) {
	C.secp256k1_scalar_get_b32((*C.uchar)(&dst[0]), &x.inner)
}

// SizeHint implements the surge.SizeHinter interface.
func (x Fn) SizeHint() int { return 32 }

// Marshal implements the surge.Marshaler interface.
func (x Fn) Marshal(w io.Writer, m int) (int, error) {
	if m < 32 {
		return m, surge.ErrMaxBytesExceeded
	}

	var bs [32]byte
	x.GetB32(bs[:])
	n, err := w.Write(bs[:])

	return m - n, err
}

// Unmarshal implements the surge.Unmarshaler interface.
func (x *Fn) Unmarshal(r io.Reader, m int) (int, error) {
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

// SetUint sets the field element to be equal to the given uint.
func (x *Fn) SetUint(v uint16) {
	// TODO: Currently we take a uint16 as an argument because a c uint is only
	// guaranteed to have at least 16 bits. Consider changing the struct to
	// have x.inner be [4]uint64 to avoid this potential information loss.
	C.secp256k1_scalar_set_int(&x.inner, C.uint(v))
}

// Add computes the addition of the two field elements and stores the result in
// the receiver.
func (x *Fn) Add(a, b *Fn) {
	// The c function returns an int that indicates whether there was overflow,
	// which we ignore.
	_ = C.secp256k1_scalar_add(&x.inner, &a.inner, &b.inner)
}

// Mul computes the multiplication of the two field elements and stores the
// result in the receiver.
func (x *Fn) Mul(a, b *Fn) {
	C.secp256k1_scalar_mul(&x.inner, &a.inner, &b.inner)
}

// Sqr computes the square of the given field element and stores the result in
// the receiver.
func (x *Fn) Sqr(a *Fn) {
	C.secp256k1_scalar_sqr(&x.inner, &a.inner)
}

// InverseInvar computes the multiplicative inverse of the given field element
// using a time invariant algorithm and stores the result in the receiver.
func (x *Fn) InverseInvar(a *Fn) {
	C.secp256k1_scalar_inverse(&x.inner, &a.inner)
}

// Inverse computes the multiplicative inverse of the given field element and
// stores the result in the receiver.
func (x *Fn) Inverse(a *Fn) {
	C.secp256k1_scalar_inverse_var(&x.inner, &a.inner)
}

// Negate computes the additive inverse of the given field element and stores
// the result in the receiver.
func (x *Fn) Negate(a *Fn) {
	C.secp256k1_scalar_negate(&x.inner, &a.inner)
}

// IsZero returns true if the field element is zero and false otherwise.
func (x *Fn) IsZero() bool {
	return int(C.secp256k1_scalar_is_zero(&x.inner)) == 1
}

// IsOne returns true if the field element is one and false otherwise.
func (x *Fn) IsOne() bool {
	return int(C.secp256k1_scalar_is_one(&x.inner)) == 1
}

// IsEven returns true if the field element is even and false otherwise.
func (x *Fn) IsEven() bool {
	return int(C.secp256k1_scalar_is_even(&x.inner)) == 1
}

// IsHigh returns true if the field element is greater than N/2 and false
// otherwise.
func (x *Fn) IsHigh() bool {
	return int(C.secp256k1_scalar_is_high(&x.inner)) == 1
}

// Eq returns true if the two field elements are equal, and false otherwise.
func (x *Fn) Eq(other *Fn) bool {
	return int(C.secp256k1_scalar_eq(&x.inner, &other.inner)) == 1
}
