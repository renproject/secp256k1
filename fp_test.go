package secp256k1_test

import (
	"crypto/rand"
	"math/big"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/secp256k1"
	"github.com/renproject/secp256k1/secp256k1tutil"
)

var _ = Describe("Fp", func() {
	trials := 1000

	// Elliptic curve group order.
	P, ok := big.NewInt(0).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	if !ok {
		panic("could not create elliptic curve group order")
	}

	// Difference between P and 2^256.
	diff, ok := big.NewInt(0).SetString("1000003d1", 16)
	if !ok {
		panic("could not create difference constant")
	}

	zero, one := NewFpFromU64(0), NewFpFromU64(1)

	// Helper functions

	randomOutOfRangeBytes := func() []byte {
		d, err := rand.Int(rand.Reader, diff)
		if err != nil {
			panic("couldn't generate random difference")
		}
		d.Add(P, d)
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
		var a, b, c Fp
		x, y, expected, actual := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a, b = RandomFp(), RandomFp()
			a.PutInt(x)
			b.PutInt(y)

			c.AddUnsafe(&a, &b)
			c.PutInt(actual)

			expected.Add(x, y)
			expected.Mod(expected, P)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should add assign correctly", func() {
		var a, b Fp
		x, y, expected, actual := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a, b = RandomFp(), RandomFp()
			a.PutInt(x)
			b.PutInt(y)

			a.AddAssignUnsafe(&b)
			a.PutInt(actual)

			expected.Add(x, y)
			expected.Mod(expected, P)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should mul correctly", func() {
		var a, b, c Fp
		x, y, expected, actual := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a, b = RandomFp(), RandomFp()
			a.PutInt(x)
			b.PutInt(y)

			c.MulUnsafe(&a, &b)
			c.PutInt(actual)

			expected.Mul(x, y)
			expected.Mod(expected, P)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should square correctly", func() {
		var a, b Fp
		x, expected, actual := new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a = RandomFp()
			a.PutInt(x)

			b.SqrUnsafe(&a)
			b.PutInt(actual)

			expected.Mul(x, x)
			expected.Mod(expected, P)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should negate correctly", func() {
		var a, b Fp
		x, expected, actual := new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a = RandomFp()
			a.PutInt(x)

			b.NegateUnsafe(&a)
			b.PutInt(actual)

			expected.Sub(P, x)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should invert correctly", func() {
		var a, b Fp
		x, expected, actual := new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a = RandomFp()
			a.PutInt(x)

			b.InvUnsafe(&a)
			b.PutInt(actual)

			expected.ModInverse(x, P)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	//
	// Properties
	//

	It("should identify the zero element", func() {
		var x Fp

		Expect(zero.IsZero()).To(BeTrue())

		for i := 0; i < trials; i++ {
			// NOTE: It is possible that this could be zero, but the chance is
			// negligible.
			x = RandomFp()

			Expect(x.IsZero()).To(BeFalse())
		}
	})

	It("should identify the one element", func() {
		var x Fp

		Expect(one.IsOne()).To(BeTrue())

		for i := 0; i < trials; i++ {
			// NOTE: It is possible that this could be one, but the chance is
			// negligible.
			x = RandomFp()

			Expect(x.IsOne()).To(BeFalse())
		}
	})

	It("should identify even elements", func() {
		var x Fp
		a := new(big.Int)

		for i := 0; i < trials; i++ {
			x = RandomFp()
			x.PutInt(a)

			Expect(x.IsEven()).To(Equal(a.Bit(0) == 0))
		}
	})

	//
	// Aliasing
	//

	It("should add correctly when the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y = x

			aliased.AddUnsafe(&x, &x)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the first argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()
			aliased = x

			aliased.AddUnsafe(&aliased, &y)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the second argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()
			aliased = y

			aliased.AddUnsafe(&x, &aliased)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the receiver and the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y = x
			aliased = x

			aliased.AddUnsafe(&aliased, &aliased)
			expected.AddUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add assign correctly when the first argument is an alias of the receiver", func() {
		var x, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			aliased = x
			expected = x

			aliased.AddAssignUnsafe(&aliased)
			expected.AddAssignUnsafe(&x)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y = x

			aliased.MulUnsafe(&x, &x)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the first argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()
			aliased = x

			aliased.MulUnsafe(&aliased, &y)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the second argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()
			aliased = y

			aliased.MulUnsafe(&x, &aliased)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the receiver and the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y = x
			aliased = x

			aliased.MulUnsafe(&aliased, &aliased)
			expected.MulUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply (no aliase) correctly when the first argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()
			aliased = x

			aliased.MulNoAliaseUnsafe(&aliased, &y)
			expected.MulNoAliaseUnsafe(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	//
	// Panics
	//

	It("should panic when adding when either argument is nil", func() {
		var x Fp
		Expect(func() { x.Add(nil, &Fp{}) }).To(Panic())
		Expect(func() { x.Add(&Fp{}, nil) }).To(Panic())
	})

	It("should panic when add assigning when the argument is nil", func() {
		var x Fp
		Expect(func() { x.AddAssign(nil) }).To(Panic())
	})

	It("should panic when multiplying when either argument is nil", func() {
		var x Fp
		Expect(func() { x.Mul(nil, &Fp{}) }).To(Panic())
		Expect(func() { x.Mul(&Fp{}, nil) }).To(Panic())
	})

	It("should panic when multiplying (no aliase) when either argument is nil", func() {
		var x Fp
		Expect(func() { x.MulNoAliase(nil, &Fp{}) }).To(Panic())
		Expect(func() { x.MulNoAliase(&Fp{}, nil) }).To(Panic())
	})

	It("should panic when squaring when the argument is nil", func() {
		var x Fp
		Expect(func() { x.Sqr(nil) }).To(Panic())
	})

	It("should panic when inverting when the argument is nil", func() {
		var x Fp
		Expect(func() { x.Inv(nil) }).To(Panic())
	})

	It("should panic when negating when the argument is nil", func() {
		var x Fp
		Expect(func() { x.Negate(nil) }).To(Panic())
	})

	It("should panic when setting bytes when the slice length is too small", func() {
		var x Fp
		var bs [31]byte
		for i := 0; i < 31; i++ {
			Expect(func() { x.SetB32(bs[:i]) }).To(Panic())
		}
	})

	It("should panic when putting bytes when the slice length is too small", func() {
		var x Fp
		var bs [31]byte
		for i := 0; i < 31; i++ {
			Expect(func() { x.PutB32(bs[:i]) }).To(Panic())
		}
	})

	//
	// Arithmetic properties
	//

	It("should remain unchanged after adding zero", func() {
		var y Fp
		for i := 0; i < trials; i++ {
			x := RandomFp()
			y.AddUnsafe(&x, &zero)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should remain unchanged after add assigning zero", func() {
		var y Fp
		for i := 0; i < trials; i++ {
			x := RandomFp()
			y = x
			y.AddAssignUnsafe(&zero)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should remain unchanged after multiplying by one", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y.MulUnsafe(&x, &one)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should remain unchanged after multiplying (no aliase) by one", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y.MulNoAliaseUnsafe(&x, &one)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should be zero after multiplying by zero", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y.MulUnsafe(&x, &zero)
			Expect(y.IsZero()).To(BeTrue())
		}
	})

	It("should be zero after multiplying (no aliase) by zero", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y.MulNoAliaseUnsafe(&x, &zero)
			Expect(y.IsZero()).To(BeTrue())
		}
	})

	It("should be zero after adding the additive inverse", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y.NegateUnsafe(&x)
			y.AddUnsafe(&y, &x)
			Expect(y.IsZero()).To(BeTrue())
		}
	})

	It("should be zero after add assigning the additive inverse", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()
			y.NegateUnsafe(&x)
			y.AddAssignUnsafe(&x)
			Expect(y.IsZero()).To(BeTrue())
		}
	})

	It("should be one after multiplying by the multiplicative inverse", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()

			// The zero element has no multiplicative inverse.
			if x.IsZero() {
				continue
			}

			y.InvUnsafe(&x)
			y.MulUnsafe(&y, &x)
			Expect(y.IsOne()).To(BeTrue())
		}
	})

	It("should be one after multiplying (no aliase) by the multiplicative inverse", func() {
		var x, y Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()

			// The zero element has no multiplicative inverse.
			if x.IsZero() {
				continue
			}

			y.InvUnsafe(&x)
			y.MulNoAliaseUnsafe(&y, &x)
			Expect(y.IsOne()).To(BeTrue())
		}
	})

	Specify("distributivity should hold", func() {
		var a, b, c, addMul, mulAdd Fp
		for i := 0; i < trials; i++ {
			a, b, c = RandomFp(), RandomFp(), RandomFp()

			// a * (b + c)
			addMul.AddUnsafe(&b, &c)
			addMul.MulUnsafe(&addMul, &a)

			// a*b + a*c
			temp := Fp{}
			mulAdd.MulUnsafe(&a, &b)
			temp.MulUnsafe(&a, &c)
			mulAdd.AddUnsafe(&mulAdd, &temp)

			Expect(addMul.Eq(&mulAdd)).To(BeTrue())
		}
	})

	Specify("addition should be commutative", func() {
		var a, b, ab, ba Fp
		for i := 0; i < trials; i++ {
			a, b = RandomFp(), RandomFp()

			ab.AddUnsafe(&a, &b)
			ba.AddUnsafe(&b, &a)

			Expect(ab.Eq(&ba)).To(BeTrue())
		}
	})

	Specify("multiplication should be commutative", func() {
		var a, b, ab, ba Fp
		for i := 0; i < trials; i++ {
			a, b = RandomFp(), RandomFp()

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
		var x, y Fp

		for i := 0; i < trials; i++ {
			x = RandomFp()
			x.PutB32(bs[:])
			y.SetB32(bs[:])
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should be equal after marshaling and unmarshaling with surge", func() {
		var bs [FpSizeMarshalled]byte
		var before, after Fp

		for i := 0; i < trials; i++ {
			before = RandomFp()

			tail, rem, err := before.Marshal(bs[:], before.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(rem).To(Equal(0))
			Expect(len(tail)).To(Equal(0))

			tail, rem, err = after.Unmarshal(bs[:], FpSize)
			Expect(err).ToNot(HaveOccurred())
			Expect(rem).To(Equal(0))
			Expect(len(tail)).To(Equal(0))

			Expect(after.Eq(&before)).To(BeTrue())
		}
	})

	It("should return an error when marshalling with a buffer that is too small", func() {
		var bs [FpSizeMarshalled - 1]byte
		var p Fp

		for i := 0; i < FpSizeMarshalled-1; i++ {
			tail, rem, err := p.Marshal(bs[:i], FpSizeMarshalled)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(FpSizeMarshalled))
			Expect(len(tail)).To(Equal(i))
		}
	})

	It("should return an error when marshalling with not enough remaining bytes", func() {
		var bs [FpSizeMarshalled]byte
		var p Fp

		for i := 0; i < FpSizeMarshalled-1; i++ {
			tail, rem, err := p.Marshal(bs[:], i)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(i))
			Expect(len(tail)).To(Equal(FpSizeMarshalled))
		}
	})

	It("should return an error when unmarshalling with a buffer that is too small", func() {
		var bs [FpSizeMarshalled - 1]byte
		var p Fp

		for i := 0; i < FpSizeMarshalled-1; i++ {
			tail, rem, err := p.Unmarshal(bs[:i], FpSizeMarshalled)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(FpSizeMarshalled))
			Expect(len(tail)).To(Equal(i))
		}
	})

	It("should return an error when unmarshalling with not enough remaining bytes", func() {
		var bs [FpSizeMarshalled]byte
		var p Fp

		for i := 0; i < FpSizeMarshalled-1; i++ {
			tail, rem, err := p.Unmarshal(bs[:], i)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(i))
			Expect(len(tail)).To(Equal(FpSizeMarshalled))
		}
	})

	It("should be normalized after setting from bytes larger than P", func() {
		var x Fp

		xInt := new(big.Int)

		for i := 0; i < trials; i++ {
			bs := randomOutOfRangeBytes()
			x.SetB32(bs)
			x.PutInt(xInt)
			Expect(xInt.Cmp(P)).To(Equal(-1))
		}
	})

	//
	// Miscellaneous
	//

	It("should be zero after clearing", func() {
		for i := 0; i < trials; i++ {
			x := RandomFp()
			x.Clear()
			Expect(x.IsZero()).To(BeTrue())
		}
	})

	It("should generate random numbers without error", func() {
		var x Fp
		var err error

		for i := 0; i < trials; i++ {
			x.Clear()
			x, err = RandomFpNoPanic()

			Expect(err).ToNot(HaveOccurred())

			// NOTE: It is possible that x is zero, but the probability is
			// negligible.
			Expect(x.IsZero()).To(BeFalse())
		}
	})

	Specify("multiplying with equal arguments should be the same as squaring", func() {
		var x, mul, sqr Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()

			sqr.SqrUnsafe(&x)
			mul.MulUnsafe(&x, &x)

			Expect(sqr.Eq(&mul)).To(BeTrue())
		}
	})

	Specify("addition should be the same as the unsafe variant", func() {
		var x, y, safe, unsafe Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()

			safe.Add(&x, &y)
			unsafe.AddUnsafe(&x, &y)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("add assign should be the same as the unsafe variant", func() {
		var x, y, safe, unsafe Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()
			safe, unsafe = x, x

			safe.AddAssign(&y)
			unsafe.AddAssignUnsafe(&y)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("multiplication should be the same as the unsafe variant", func() {
		var x, y, safe, unsafe Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()

			safe.Mul(&x, &y)
			unsafe.MulUnsafe(&x, &y)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("multiplication (no aliase) should be the same as the unsafe variant", func() {
		var x, y, safe, unsafe Fp
		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()

			safe.MulNoAliase(&x, &y)
			unsafe.MulNoAliaseUnsafe(&x, &y)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("squaring should be the same as the unsafe variant", func() {
		var x, safe, unsafe Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()

			safe.Sqr(&x)
			unsafe.SqrUnsafe(&x)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("inversion should be the same as the unsafe variant", func() {
		var x, safe, unsafe Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()

			safe.Inv(&x)
			unsafe.InvUnsafe(&x)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("negation should be the same as the unsafe variant", func() {
		var x, safe, unsafe Fp
		for i := 0; i < trials; i++ {
			x = RandomFp()

			safe.Negate(&x)
			unsafe.NegateUnsafe(&x)

			Expect(safe.Eq(&unsafe)).To(BeTrue())
		}
	})

	Specify("setting and constructing a big.Int using a field element should be consistent", func() {
		var x Fp
		a := new(big.Int)

		for i := 0; i < trials; i++ {
			x = RandomFp()
			x.PutInt(a)

			Expect(x.Int().Cmp(a)).To(Equal(0))
		}
	})

	It("should return an error when there is a read error when safely generating a random field element", func() {
		secp256k1tutil.UseErrReader(func() {
			x, err := RandomFpNoPanic()
			Expect(err).To(HaveOccurred())
			Expect(x.IsZero()).To(BeTrue())
		})
	})

	It("should panic when there is a read error when generating a random field element", func() {
		secp256k1tutil.UseErrReader(func() {
			Expect(func() { RandomFp() }).To(Panic())
		})
	})
})
