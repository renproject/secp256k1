package secp256k1_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/secp256k1"
)

var _ = Describe("Fn", func() {
	trials := 1000

	zero, one := NewFnFromUint(0), NewFnFromUint(1)

	It("should be zero after clearing", func() {
		for i := 0; i < trials; i++ {
			x := RandomFn()
			x.Clear()
			Expect(x.IsZero()).To(BeTrue())
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

	Specify("distributivty should hold", func() {
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
	//
	//

	Specify("multiplying with equal arguments should be the same as squaring", func() {
		var x, mul, sqr Fn
		for i := 0; i < trials; i++ {
			x = RandomFn()

			sqr.Sqr(&x)
			mul.Mul(&x, &x)

			Expect(sqr.Eq(&mul)).To(BeTrue())
		}
	})

	It("should be equal after converting to and from bytes", func() {
		var bs [32]byte
		var y Fn
		for i := 0; i < trials; i++ {
			x := RandomFn()
			x.GetB32(bs[:])
			y.SetB32(bs[:])
			Expect(y.Eq(&x)).To(BeTrue())
		}
	})
})
