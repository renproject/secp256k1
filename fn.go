package secp256k1

/*

#define USE_NUM_GMP

// TODO: These should be chosen based on the system architecture, if possible.
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
	"unsafe"
)

// Fn represents an element of the field defined by the prime N, where N is the
// order of the elliptic curve group secp256k1.
type Fn struct {
	inner C.secp256k1_scalar
}

// NewFnFromUint returns a new field element equal to the given unsigned
// integer.
func NewFnFromUint(v uint) Fn {
	x := Fn{}
	x.setUint(v)
	return x
}

// RandomFn returns a random field element.
//
// Panics: This function will panic if there was an error reading bytes from
// the random source.
func RandomFn() Fn {
	var bs [32]byte
	_, err := rand.Read(bs[:])
	if err != nil {
		panic(fmt.Sprintf("could not generate random bytes: %v", err))
	}
	x := Fn{}
	x.SetB32(bs[:])
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
	x.SetB32(bs[:])
	return x, nil
}

// Clear sets the underlying data of the structure to zero. This will leave it
// in a state which is a representation of the zero element.
func (x *Fn) Clear() {
	C.secp256k1_scalar_clear(&x.inner)
}

func (x *Fn) getBits(offset, count uint) uint {
	// TODO: Make sure that the arguments to this (go) function have the right
	// type, so that when they are cast to the c type `unsigned int` nothing
	// bad happens.
	return uint(C.secp256k1_scalar_get_bits(&x.inner, C.uint(offset), C.uint(count)))
}

func (x *Fn) getBitsVar(offset, count uint) uint {
	// TODO: Make sure that the arguments to this (go) function have the right
	// type, so that when they are cast to the c type `unsigned int` nothing
	// bad happens.
	return uint(C.secp256k1_scalar_get_bits_var(&x.inner, C.uint(offset), C.uint(count)))
}

// SetB32 sets the field element to be equal to the given byte slice,
// interepreted as big endian. The field element will be reduced modulo N. The
// argument `overflow` will be non zero if the bytes represented a number
// greater than or equal to N, and zero otherwise.
//
// Panics: If the byte slice has length less than 32, this function will panic.
func (x *Fn) SetB32(bs []byte) bool {
	// TODO: Check type conversions.
	var overflow int
	C.secp256k1_scalar_set_b32(
		&x.inner,
		(*C.uchar)(&bs[0]),
		(*C.int)(unsafe.Pointer(&overflow)),
	)
	return overflow != 0
}

func (x *Fn) setB32SecKey(bs []byte) int {
	return int(C.secp256k1_scalar_set_b32_seckey(&x.inner, (*C.uchar)(C.CBytes(bs))))
}

func (x *Fn) setUint(v uint) {
	// TODO: Check type conversion.
	C.secp256k1_scalar_set_int(&x.inner, C.uint(v))
}

// GetB32 stores the bytes of the field element into destination in big endian
// form.
func (x Fn) GetB32(dst []byte) {
	C.secp256k1_scalar_get_b32((*C.uchar)(&dst[0]), &x.inner)
}

// Add computes the addition of the two field elements and stores the result in
// the receiver.
func (x *Fn) Add(a, b *Fn) {
	// The c function returns an int that indicates whether there was overflow,
	// which we ignore.
	_ = C.secp256k1_scalar_add(&x.inner, &a.inner, &b.inner)
}

func (x *Fn) cAddBit(bit uint, flag int) {
	C.secp256k1_scalar_cadd_bit(&x.inner, C.uint(bit), C.int(flag))
}

// Mul computes the multiplication of the two field elements and stores the
// result in the receiver.
func (x *Fn) Mul(a, b *Fn) {
	C.secp256k1_scalar_mul(&x.inner, &a.inner, &b.inner)
}

func (x *Fn) shrInt(n int) int {
	return int(C.secp256k1_scalar_shr_int(&x.inner, C.int(n)))
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

func (x *Fn) condNegate(flag int) int {
	return int(C.secp256k1_scalar_cond_negate(&x.inner, C.int(flag)))
}

// NOTE: The following functions are not included and correspond to the
// USE_NUM_NONE switch:
//
// secp256k1_scalar_get_num
// secp256k1_scalar_order_get_num

// Eq returns true if the two field elements are equal, and false otherwise.
func (x *Fn) Eq(other *Fn) bool {
	return int(C.secp256k1_scalar_eq(&x.inner, &other.inner)) == 1
}

// NOTE: The following functions are not included and correspond to the
// USE_ENDOMORPHISM switch:
//
// secp256k1_scalar_split_128
// secp256k1_scalar_split_lambda

func (x *Fn) mulShiftVar(a, b *Fn, shift uint) {
	// TODO: Check type conversion.
	C.secp256k1_scalar_mul_shift_var(&x.inner, &a.inner, &b.inner, C.uint(shift))
}

func (x *Fn) cMov(a *Fn, flag int) {
	C.secp256k1_scalar_cmov(&x.inner, &a.inner, C.int(flag))
}
