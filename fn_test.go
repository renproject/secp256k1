package secp256k1_test

import (
	"bytes"
	"crypto/rand"
	"math/big"
	mrand "math/rand"

	"github.com/renproject/secp256k1/testutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/secp256k1"
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

	zero, one := NewFnFromUint(0), NewFnFromUint(1)

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
			a.GetInt(x)
			b.GetInt(y)

			c.Add(&a, &b)
			c.GetInt(actual)

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
			a.GetInt(x)
			b.GetInt(y)

			c.Mul(&a, &b)
			c.GetInt(actual)

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
			a.GetInt(x)

			b.Sqr(&a)
			b.GetInt(actual)

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
			a.GetInt(x)

			b.Negate(&a)
			b.GetInt(actual)

			expected.Sub(N, x)

			Expect(actual.Cmp(expected)).To(Equal(0))
		}
	})

	It("should invert correctly", func() {
		var a, b Fn
		x, expected, actual := new(big.Int), new(big.Int), new(big.Int)
		for i := 0; i < trials; i++ {
			a = RandomFn()
			a.GetInt(x)

			b.Inverse(&a)
			b.GetInt(actual)

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
			x.GetInt(a)

			Expect(x.IsEven()).To(Equal(a.Bit(0) == 0))
		}
	})

	It("should identify high elements", func() {
		var x Fn
		a := new(big.Int)

		Expect(N2Fn.IsHigh()).To(BeFalse())

		for i := 0; i < trials; i++ {
			x = RandomFn()
			x.GetInt(a)

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

			aliased.Add(&x, &x)
			expected.Add(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the first argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = x

			aliased.Add(&aliased, &y)
			expected.Add(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the second argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = y

			aliased.Add(&x, &aliased)
			expected.Add(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add correctly when the receiver and the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y = x
			aliased = x

			aliased.Add(&aliased, &aliased)
			expected.Add(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y = x

			aliased.Mul(&x, &x)
			expected.Mul(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the first argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = x

			aliased.Mul(&aliased, &y)
			expected.Mul(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the second argument is an alias of the receiver", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x, y = RandomFn(), RandomFn()
			aliased = y

			aliased.Mul(&x, &aliased)
			expected.Mul(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	It("should multiply correctly when the receiver and the arguments are aliases of each other", func() {
		var x, y, aliased, expected Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y = x
			aliased = x

			aliased.Mul(&aliased, &aliased)
			expected.Mul(&x, &y)

			Expect(aliased.Eq(&expected)).To(BeTrue())
		}
	})

	//
	// Arithmetic properties
	//

	It("should remain unchanged after adding zero", func() {
		var y Fn
		for i := 0; i < trials; i++ {
			x := RandomFn()
			y.Add(&x, &zero)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should remain unchanged after multiplying by one", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y.Mul(&x, &one)
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should be zero after multiplying by zero", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y.Mul(&x, &zero)
			Expect(y.IsZero()).To(BeTrue())
		}
	})

	It("should be zero after adding the additive inverse", func() {
		var x, y Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()
			y.Negate(&x)
			y.Add(&y, &x)
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

			y.Inverse(&x)
			y.Mul(&y, &x)
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

			y.InverseInvar(&x)
			y.Mul(&y, &x)
			Expect(y.IsOne()).To(BeTrue())
		}
	})

	Specify("distributivity should hold", func() {
		var a, b, c, addMul, mulAdd Fn
		for i := 0; i < trials; i++ {
			a, b, c = RandomFn(), RandomFn(), RandomFn()

			// a * (b + c)
			addMul.Add(&b, &c)
			addMul.Mul(&addMul, &a)

			// a*b + a*c
			temp := Fn{}
			mulAdd.Mul(&a, &b)
			temp.Mul(&a, &c)
			mulAdd.Add(&mulAdd, &temp)

			Expect(addMul.Eq(&mulAdd)).To(BeTrue())
		}
	})

	Specify("addition should be commutative", func() {
		var a, b, ab, ba Fn
		for i := 0; i < trials; i++ {
			a, b = RandomFn(), RandomFn()

			ab.Add(&a, &b)
			ba.Add(&b, &a)

			Expect(ab.Eq(&ba)).To(BeTrue())
		}
	})

	Specify("multiplication should be commutative", func() {
		var a, b, ab, ba Fn
		for i := 0; i < trials; i++ {
			a, b = RandomFn(), RandomFn()

			ab.Mul(&a, &b)
			ba.Mul(&b, &a)

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
			x.GetB32(bs[:])
			y.SetB32(bs[:])
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should be equal after marshaling and unmarshaling with surge", func() {
		var bs [32]byte
		var x, y Fn

		buf := bytes.NewBuffer(bs[:])
		max := x.SizeHint()

		for i := 0; i < trials; i++ {
			x = RandomFn()

			buf.Reset()
			m, err := x.Marshal(buf, max)
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))

			m, err = y.Unmarshal(buf, max)
			Expect(err).ToNot(HaveOccurred())
			Expect(m).To(Equal(0))

			Expect(y.Eq(&x)).To(BeTrue())
		}
	})

	It("should return an error when marshaling with not enough remaining bytes", func() {
		var x Fn

		for i := 0; i < trials; i++ {
			x = RandomFn()
			max := mrand.Intn(x.SizeHint())

			m, err := x.Marshal(nil, max)
			Expect(err).To(HaveOccurred())
			Expect(m).To(Equal(max))
		}
	})

	It("should return an error when unmarshaling with not enough remaining bytes", func() {
		var x Fn

		for i := 0; i < trials; i++ {
			x = RandomFn()

			max := mrand.Intn(x.SizeHint())
			m, err := x.Unmarshal(nil, max)
			Expect(err).To(HaveOccurred())
			Expect(m).To(Equal(max))
		}
	})

	It("should return an error when unmarshaling and the reader returns an error", func() {
		var bs [1]byte
		var x Fn

		buf := bytes.NewBuffer(bs[:0])
		max := x.SizeHint()

		for i := 0; i < trials; i++ {
			x = RandomFn()
			buf.Reset()

			m, err := x.Unmarshal(buf, max)
			Expect(err).To(HaveOccurred())
			Expect(m).To(Equal(max))
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
			x.GetB32(bs[:])
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
			x, err = RandomFnSafe()

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

			sqr.Sqr(&x)
			mul.Mul(&x, &x)

			Expect(sqr.Eq(&mul)).To(BeTrue())
		}
	})

	Specify("setting and constructing a big.Int using a field element should be consistent", func() {
		var x Fn
		a := new(big.Int)

		for i := 0; i < trials; i++ {
			x = RandomFn()
			x.GetInt(a)

			Expect(x.Int().Cmp(a)).To(Equal(0))
		}
	})

	It("should return an error when there is a read error when safely generating a random field element", func() {
		testutil.UseErrReader(func() {
			x, err := RandomFnSafe()
			Expect(err).To(HaveOccurred())
			Expect(x.IsZero()).To(BeTrue())
		})
	})

	It("should panic when there is a read error when generating a random field element", func() {
		testutil.UseErrReader(func() {
			Expect(func() { RandomFn() }).To(Panic())
		})
	})
})
