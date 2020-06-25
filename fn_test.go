package secp256k1_test

import (
	"crypto/rand"
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/secp256k1"
	"github.com/renproject/secp256k1/secp256k1tutil"
)

var _ = Describe("Fn", func() {
	trials := 1000

	// Elliptic curve group order.
	N, ok := big.NewInt(0).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	if !ok {
		panic("could not create elliptic curve group order")
	}

	// big.Int representation of N/2.
	N2Int, ok := big.NewInt(0).SetString(
		"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
		16,
	)
	if !ok {
		panic("could not create high threshold")
	}

	// Fn representation of N/2.
	var N2Fn Fn
	{
		bs := [32]byte{
			0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D,
			0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
		}

		N2Fn.SetB32(bs[:])
	}

	// Difference between N and 2^256.
	diff, ok := big.NewInt(0).SetString("14551231950B75FC4402DA1732FC9BEBF", 16)
	if !ok {
		panic("could not create difference constant")
	}

	zero, one := NewFnFromU16(0), NewFnFromU16(1)

	// Helper functions

	randomOutOfRangeBytes := func() []byte {
		d, err := rand.Int(rand.Reader, diff)
		if err != nil {
			panic("couldn't generate random difference")
		}
		d.Add(N, d)
		bs := d.Bytes()
		if len(bs) != 32 {
			panic("unexpected slice length")
		}
		return bs
	}

	//
	// Arithmetic
	//

	It("should add correctly", func() {
		var a, b, c Fn
		x, y, expected, actual := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a, b = RandomFn(), RandomFn()
			a.PutInt(x)
			b.PutInt(y)

			c.AddUnsafe(&a, &b)
			c.PutInt(actual)

			expected.Add(x, y)
			expected.Mod(expected, N)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should mul correctly", func() {
		var a, b, c Fn
		x, y, expected, actual := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a, b = RandomFn(), RandomFn()
			a.PutInt(x)
			b.PutInt(y)

			c.MulUnsafe(&a, &b)
			c.PutInt(actual)

			expected.Mul(x, y)
			expected.Mod(expected, N)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should square correctly", func() {
		var a, b Fn
		x, expected, actual := new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a = RandomFn()
			a.PutInt(x)

			b.SqrUnsafe(&a)
			b.PutInt(actual)

			expected.Mul(x, x)
			expected.Mod(expected, N)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should negate correctly", func() {
		var a, b Fn
		x, expected, actual := new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a = RandomFn()
			a.PutInt(x)

			b.NegateUnsafe(&a)
			b.PutInt(actual)

			expected.Sub(N, x)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should invert correctly", func() {
		var a, b Fn
		x, expected, actual := new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a = RandomFn()
			a.PutInt(x)

			b.InverseUnsafe(&a)
			b.PutInt(actual)

			expected.ModInverse(x, N)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	//
	// Properties
	//

	It("should identify the zero element", func() {
		var x Fn

		Expect(zero.IsZero()).To(BeTrue())

		for i := 0; i < trials; i++ {
			// NOTE: It is possible that this could be zero, but the chance is
			// negligible.
			x = RandomFn()

			Expect(x.IsZero()).To(BeFalse())
		}
	})

	It("should identify the one element", func() {
		var x Fn

		Expect(one.IsOne()).To(BeTrue())

		for i := 0; i < trials; i++ {
			// NOTE: It is possible that this could be one, but the chance is
			// negligible.
			x = RandomFn()

			Expect(x.IsOne()).To(BeFalse())
		}
	})

	It("should identify even elements", func() {
		var x Fn
		a := new(big.Int)

		for i := 0; i < trials; i++ {
			x = RandomFn()
			x.PutInt(a)

			Expect(x.IsEven()).To(Equal(a.Bit(0) == 0))
		}
	})

	It("should identify high elements", func() {
		var x Fn
		a := new(big.Int)

		Expect(N2Fn.IsHigh()).To(BeFalse())

		for i := 0; i < trials; i++ {
			x = RandomFn()
			x.PutInt(a)

			Expect(x.IsHigh()).To(Equal(a.Cmp(N2Int) == 1))
		}
	})

	//
	// Aliasing
	//

	It("should add correctly when the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y = x

			aliased.AddUnsafe(&x, &x)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the first argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = x

			aliased.AddUnsafe(&aliased, &y)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the second argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = y

			aliased.AddUnsafe(&x, &aliased)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the receiver and the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y = x
			aliased = x

			aliased.AddUnsafe(&aliased, &aliased)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y = x

			aliased.MulUnsafe(&x, &x)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the first argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = x

			aliased.MulUnsafe(&aliased, &y)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the second argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = y

			aliased.MulUnsafe(&x, &aliased)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the receiver and the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y = x
			aliased = x

			aliased.MulUnsafe(&aliased, &aliased)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	//
	// Panics
	//

	It("should panic when adding when either argument is nil", func() {
		var x Fn
		Expect(func() { x.Add(nil, &Fn{}) }).To(Panic())
		Expect(func() { x.Add(&Fn{}, nil) }).To(Panic())
	})

	It("should panic when multiplying when either argument is nil", func() {
		var x Fn
		Expect(func() { x.Mul(nil, &Fn{}) }).To(Panic())
		Expect(func() { x.Mul(&Fn{}, nil) }).To(Panic())
	})

	It("should panic when squaring when the argument is nil", func() {
		var x Fn
		Expect(func() { x.Sqr(nil) }).To(Panic())
	})

	It("should panic when inverting (invar) when the argument is nil", func() {
		var x Fn
		Expect(func() { x.InverseInvar(nil) }).To(Panic())
	})

	It("should panic when inverting when the argument is nil", func() {
		var x Fn
		Expect(func() { x.Inverse(nil) }).To(Panic())
	})

	It("should panic when negating when the argument is nil", func() {
		var x Fn
		Expect(func() { x.Negate(nil) }).To(Panic())
	})

	It("should panic when setting bytes when the slice length is too small", func() {
		var x Fn
		var bs [31]byte
		for i := 0; i < 31; i++ {
			Expect(func() { x.SetB32(bs[:i]) }).To(Panic())
		}
	})

	It("should panic when setting bytes (seckey) when the slice length is too small", func() {
		var x Fn
		var bs [31]byte
		for i := 0; i < 31; i++ {
			Expect(func() { x.SetB32SecKey(bs[:i]) }).To(Panic())
		}
	})

	It("should panic when putting bytes when the slice length is too small", func() {
		var x Fn
		var bs [31]byte
		for i := 0; i < 31; i++ {
			Expect(func() { x.PutB32(bs[:i]) }).To(Panic())
		}
	})

	//
	// Arithmetic properties
	//

	It("should remain unchanged after adding zero", func() {
		var y Fn
		for i := 0; i < trials; i++ {
			x := RandomFn()
			y.AddUnsafe(&x, &zero)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should remain unchanged after multiplying by one", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y.MulUnsafe(&x, &one)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should be zero after multiplying by zero", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y.MulUnsafe(&x, &zero)
			Expect(y.IsZero()).To(BeTrue())
		}
	})

	It("should be zero after adding the additive inverse", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y.NegateUnsafe(&x)
			y.AddUnsafe(&y, &x)
			Expect(y.IsZero()).To(BeTrue())
		}
	})

	It("should be one after multiplying by the multiplicative inverse", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			// The zero element has no multiplicative inverse.
			if x.IsZero() {
				continue
			}

			y.InverseUnsafe(&x)
			y.MulUnsafe(&y, &x)
			Expect(y.IsOne()).To(BeTrue())
		}
	})

	It("should be one after multiplying by the multiplicative inverse (time invariant method)", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			// The zero element has no multiplicative inverse.
			if x.IsZero() {
				continue
			}

			y.InverseInvarUnsafe(&x)
			y.MulUnsafe(&y, &x)
			Expect(y.IsOne()).To(BeTrue())
		}
	})

	Specify("distributivity should hold", func() {
		var a, b, c, addMul, mulAdd Fn
		for i := 0; i < trials; i++ {
			a, b, c = RandomFn(), RandomFn(), RandomFn()

			// a * (b + c)
			addMul.AddUnsafe(&b, &c)
			addMul.MulUnsafe(&addMul, &a)

			// a*b + a*c
			temp := Fn{}
			mulAdd.MulUnsafe(&a, &b)
			temp.MulUnsafe(&a, &c)
			mulAdd.AddUnsafe(&mulAdd, &temp)

			Expect(addMul.Eq(&mulAdd)).To(BeTrue())
		}
	})

	Specify("addition should be commutative", func() {
		var a, b, ab, ba Fn
		for i := 0; i < trials; i++ {
			a, b = RandomFn(), RandomFn()

			ab.AddUnsafe(&a, &b)
			ba.AddUnsafe(&b, &a)

			Expect(ab.Eq(&ba)).To(BeTrue())
		}
	})

	Specify("multiplication should be commutative", func() {
		var a, b, ab, ba Fn
		for i := 0; i < trials; i++ {
			a, b = RandomFn(), RandomFn()

			ab.MulUnsafe(&a, &b)
			ba.MulUnsafe(&b, &a)

			Expect(ab.Eq(&ba)).To(BeTrue())
		}
	})

	//
	// Marshalling
	//

	It("should be equal after converting to and from bytes", func() {
		var bs [32]byte
		var x, y Fn

		for i := 0; i < trials; i++ {
			x = RandomFn()
			x.PutB32(bs[:])
			y.SetB32(bs[:])
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should be equal after marshaling and unmarshaling with surge", func() {
		var bs [FnSizeMarshalled]byte
		var before, after Fn

		for i := 0; i < trials; i++ {
			before = RandomFn()

			tail, rem, err := before.Marshal(bs[:], before.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(rem).To(Equal(0))
			Expect(len(tail)).To(Equal(0))

			tail, rem, err = after.Unmarshal(bs[:], FnSize)
			Expect(err).ToNot(HaveOccurred())
			Expect(rem).To(Equal(0))
			Expect(len(tail)).To(Equal(0))

			Expect(after.Eq(&before)).To(BeTrue())
		}
	})

	It("should return an error when marshalling with a buffer that is too small", func() {
		var bs [FnSizeMarshalled - 1]byte
		var p Fn

		for i := 0; i < FnSizeMarshalled-1; i++ {
			tail, rem, err := p.Marshal(bs[:i], FnSizeMarshalled)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(FnSizeMarshalled))
			Expect(len(tail)).To(Equal(i))
		}
	})

	It("should return an error when marshalling with not enough remaining bytes", func() {
		var bs [FnSizeMarshalled]byte
		var p Fn

		for i := 0; i < FnSizeMarshalled-1; i++ {
			tail, rem, err := p.Marshal(bs[:], i)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(i))
			Expect(len(tail)).To(Equal(FnSizeMarshalled))
		}
	})

	It("should return an error when unmarshalling with a buffer that is too small", func() {
		var bs [FnSizeMarshalled - 1]byte
		var p Fn

		for i := 0; i < FnSizeMarshalled-1; i++ {
			tail, rem, err := p.Unmarshal(bs[:i], FnSizeMarshalled)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(FnSizeMarshalled))
			Expect(len(tail)).To(Equal(i))
		}
	})

	It("should return an error when unmarshalling with not enough remaining bytes", func() {
		var bs [FnSizeMarshalled]byte
		var p Fn

		for i := 0; i < FnSizeMarshalled-1; i++ {
			tail, rem, err := p.Unmarshal(bs[:], i)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(i))
			Expect(len(tail)).To(Equal(FnSizeMarshalled))
		}
	})

	It("should identify bytes that represent invalid private keys", func() {
		var x Fn

		// The zero element is an invalid private key.
		bs := [32]byte{}
		ok := x.SetB32SecKey(bs[:])
		Expect(ok).To(BeFalse())

		// Elements greater than or equal to N should be marked as invalid.
		for i := 0; i < trials; i++ {
			bs := randomOutOfRangeBytes()
			ok := x.SetB32SecKey(bs[:])
			Expect(ok).To(BeFalse())
		}

		// Elements already reduced modulo N should be marked as valid.
		for i := 0; i < trials; i++ {
			// NOTE: It is possible that this will be zero, but the probability
			// is negligible.
			x = RandomFn()
			x.PutB32(bs[:])
			ok := x.SetB32SecKey(bs[:])
			Expect(ok).To(BeTrue())
		}
	})

	//
	// Miscellaneous
	//

	It("should be zero after clearing", func() {
		for i := 0; i < trials; i++ {
			x := RandomFn()
			x.Clear()
			Expect(x.IsZero()).To(BeTrue())
		}
	})

	It("should generate random numbers without error", func() {
		var x Fn
		var err error

		for i := 0; i < trials; i++ {
			x.Clear()
			x, err = RandomFnNoPanic()

			Expect(err).ToNot(HaveOccurred())

			// NOTE: It is possible that x is zero, but the probability is
			// negligible.
			Expect(x.IsZero()).To(BeFalse())
		}
	})

	Specify("multiplying with equal arguments should be the same as squaring", func() {
		var x, mul, sqr Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			sqr.SqrUnsafe(&x)
			mul.MulUnsafe(&x, &x)

			Expect(sqr.Eq(&mul)).To(BeTrue())
		}
	})

	Specify("addition should be the same as the unsafe variant", func() {
		var x, y, safe, unsafe Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()

			safe.Add(&x, &y)
			unsafe.AddUnsafe(&x, &y)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("multiplication should be the same as the unsafe variant", func() {
		var x, y, safe, unsafe Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()

			safe.Mul(&x, &y)
			unsafe.MulUnsafe(&x, &y)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("squaring should be the same as the unsafe variant", func() {
		var x, safe, unsafe Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			safe.Sqr(&x)
			unsafe.SqrUnsafe(&x)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("inversion (invar) should be the same as the unsafe variant", func() {
		var x, safe, unsafe Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			safe.InverseInvar(&x)
			unsafe.InverseInvarUnsafe(&x)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("inversion should be the same as the unsafe variant", func() {
		var x, safe, unsafe Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			safe.Inverse(&x)
			unsafe.InverseUnsafe(&x)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("negation should be the same as the unsafe variant", func() {
		var x, safe, unsafe Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			safe.Negate(&x)
			unsafe.NegateUnsafe(&x)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("setting and constructing a big.Int using a field element should be consistent", func() {
		var x Fn
		a := new(big.Int)

		for i := 0; i < trials; i++ {
			x = RandomFn()
			x.PutInt(a)

			Expect(x.Int().Cmp(a)).To(Equal(0))
		}
	})

	It("should return an error when there is a read error when safely generating a random field element", func() {
		secp256k1tutil.UseErrReader(func() {
			x, err := RandomFnNoPanic()
			Expect(err).To(HaveOccurred())
			Expect(x.IsZero()).To(BeTrue())
		})
	})

	It("should panic when there is a read error when generating a random field element", func() {
		secp256k1tutil.UseErrReader(func() {
			Expect(func() { RandomFn() }).To(Panic())
		})
	})
})
