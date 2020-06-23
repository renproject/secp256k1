package secp256k1_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	ec "github.com/ethereum/go-ethereum/crypto/secp256k1"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	. "github.com/renproject/secp256k1"
)

var _ = Describe("Point", func() {
	trials := 1000

	inf := NewPointInfinity()

	copyLeftPadZero := func(dst, src []byte) {
		for i := 0; i < 32-len(src); i++ {
			dst[i] = 0
		}
		copy(dst[32-len(src):], src)
	}

	It("should correctly construct points from coordinates", func() {
		var a Point
		var x, y Fp
		var ax, ay Fp

		for i := 0; i < trials; i++ {
			x, y = RandomFp(), RandomFp()
			a = NewPointFromXY(&x, &y)

			ax, ay = a.XY()

			Expect(ax.Eq(&x)).To(BeTrue())
			Expect(ay.Eq(&y)).To(BeTrue())
		}
	})

	It("should compare points correctly", func() {
		var a, b Point

		// Points at infinity should be equal.
		a, b = inf, inf
		Expect(a.Eq(&b)).To(BeTrue())
		Expect(inf.Eq(&inf)).To(BeTrue())

		for i := 0; i < trials; i++ {
			a, b = RandomPoint(), RandomPoint()

			// Points on the curve should not be equal to the point at
			// infinity.
			Expect(a.Eq(&inf)).To(BeFalse())
			Expect(inf.Eq(&a)).To(BeFalse())

			// Two random points should not be equal except with negligible
			// probability.
			Expect(a.Eq(&b)).To(BeFalse())

			// A point should equal itself.
			b = a
			Expect(a.Eq(&a)).To(BeTrue())
			Expect(a.Eq(&b)).To(BeTrue())
		}
	})

	It("should compute scalar multiples of the generator correctly", func() {
		var scalar Fn
		var xf, yf Fp
		var actual, expected Point
		var bs [32]byte

		x, y := new(big.Int), new(big.Int)

		for i := 0; i < trials; i++ {
			scalar = RandomFn()
			scalar.PutB32(bs[:])

			actual.BaseExp(&scalar)

			x, y = ec.S256().ScalarBaseMult(bs[:])
			copyLeftPadZero(bs[:], x.Bytes())
			xf.SetB32(bs[:])
			copyLeftPadZero(bs[:], y.Bytes())
			yf.SetB32(bs[:])
			expected.SetXY(&xf, &yf)

			Expect(actual.Eq(&expected)).To(BeTrue())
		}
	})

	It("should compute scalar multiples of curve points correctly", func() {
		var scalar Fn
		var xf, yf Fp
		var axf, ayf Fp
		var actual, expected, a Point
		var bs [32]byte

		x, y := new(big.Int), new(big.Int)
		ax, ay := new(big.Int), new(big.Int)

		for i := 0; i < trials; i++ {
			a = RandomPoint()
			axf, ayf = a.XY()
			axf.PutInt(ax)
			ayf.PutInt(ay)

			scalar = RandomFn()
			scalar.PutB32(bs[:])

			actual.Scale(&a, &scalar)

			x, y = ec.S256().ScalarMult(ax, ay, bs[:])
			copyLeftPadZero(bs[:], x.Bytes())
			xf.SetB32(bs[:])
			copyLeftPadZero(bs[:], y.Bytes())
			yf.SetB32(bs[:])
			expected.SetXY(&xf, &yf)

			Expect(actual.Eq(&expected)).To(BeTrue())
		}
	})

	It("should compute extended scalar multiples correctly", func() {
		var scalar Fn
		var actual, expected, a Point

		for i := 0; i < trials; i++ {
			a = RandomPoint()
			scalar = RandomFn()

			// When the point is not the point at infinity, it should be the
			// same as the unextended function.
			actual.ScaleExt(&a, &scalar)
			expected.Scale(&a, &scalar)

			Expect(actual.Eq(&expected)).To(BeTrue())

			// When the point is the point at infinity, the result should also
			// be the point at infinity.
			actual.ScaleExt(&inf, &scalar)
			expected = inf

			Expect(actual.Eq(&expected)).To(BeTrue())
		}
	})

	It("should add finite curve points correctly", func() {
		var xf, yf Fp
		var axf, ayf, bxf, byf Fp
		var actual, expected, a, b Point
		var bs [32]byte

		x, y := new(big.Int), new(big.Int)
		ax, ay, bx, by := new(big.Int), new(big.Int), new(big.Int), new(big.Int)

		for i := 0; i < trials; i++ {
			a, b = RandomPoint(), RandomPoint()
			axf, ayf = a.XY()
			bxf, byf = b.XY()
			axf.PutInt(ax)
			ayf.PutInt(ay)
			bxf.PutInt(bx)
			byf.PutInt(by)

			actual.Add(&a, &b)

			x, y = ec.S256().Add(ax, ay, bx, by)
			copyLeftPadZero(bs[:], x.Bytes())
			xf.SetB32(bs[:])
			copyLeftPadZero(bs[:], y.Bytes())
			yf.SetB32(bs[:])
			expected.SetXY(&xf, &yf)

			Expect(actual.Eq(&expected)).To(BeTrue())

			// Adding the point at infinity should be the identity operation.
			expected = a

			actual.Add(&a, &inf)
			Expect(actual.Eq(&expected)).To(BeTrue())

			actual.Add(&inf, &a)
			Expect(actual.Eq(&expected)).To(BeTrue())

			// Adding two points at infinity should give the point at infinity.
			a = inf
			b = inf
			actual.Add(&a, &b)
			expected = inf

			Expect(actual.Eq(&expected)).To(BeTrue())
		}
	})

	//
	// Marshalling
	//

	It("should be equal after converting to and from bytes", func() {
		var bs [33]byte
		var before, after Point

		// Point at infinity.
		before = inf

		before.PutBytes(bs[:])
		err := after.SetBytes(bs[:])
		Expect(err).ToNot(HaveOccurred())

		Expect(before.Eq(&after)).To(BeTrue())

		// Random points.
		for i := 0; i < trials; i++ {
			before = RandomPoint()

			before.PutBytes(bs[:])
			err := after.SetBytes(bs[:])
			Expect(err).ToNot(HaveOccurred())

			Expect(before.Eq(&after)).To(BeTrue())
		}
	})

	It("should be equal after marshaling and unmarshaling with surge", func() {
		var bs [33]byte
		var before, after Point

		for i := 0; i < trials; i++ {
			before = RandomPoint()

			tail, rem, err := before.Marshal(bs[:], before.SizeHint())
			Expect(err).ToNot(HaveOccurred())
			Expect(rem).To(Equal(0))
			Expect(len(tail)).To(Equal(0))

			tail, rem, err = after.Unmarshal(bs[:], PointSize)
			Expect(err).ToNot(HaveOccurred())
			Expect(rem).To(Equal(0))
			Expect(len(tail)).To(Equal(0))

			Expect(after.Eq(&before)).To(BeTrue())
		}
	})

	It("should return an error when marshalling with a buffer that is too small", func() {
		var bs [PointSizeMarshalled - 1]byte
		var p Point

		for i := 0; i < PointSizeMarshalled-1; i++ {
			tail, rem, err := p.Marshal(bs[:i], PointSizeMarshalled)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(PointSizeMarshalled))
			Expect(len(tail)).To(Equal(i))
		}
	})

	It("should return an error when marshalling with not enough remaining bytes", func() {
		var bs [PointSizeMarshalled]byte
		var p Point

		for i := 0; i < PointSizeMarshalled-1; i++ {
			tail, rem, err := p.Marshal(bs[:], i)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(i))
			Expect(len(tail)).To(Equal(PointSizeMarshalled))
		}
	})

	It("should return an error when unmarshalling with a buffer that is too small", func() {
		var bs [PointSizeMarshalled - 1]byte
		var p Point

		for i := 0; i < PointSizeMarshalled-1; i++ {
			tail, rem, err := p.Unmarshal(bs[:i], PointSizeMarshalled)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(PointSizeMarshalled))
			Expect(len(tail)).To(Equal(i))
		}
	})

	It("should return an error when unmarshalling with not enough remaining bytes", func() {
		var bs [PointSizeMarshalled]byte
		var p Point

		for i := 0; i < PointSizeMarshalled-1; i++ {
			tail, rem, err := p.Unmarshal(bs[:], i)
			Expect(err).To(HaveOccurred())
			Expect(rem).To(Equal(i))
			Expect(len(tail)).To(Equal(PointSizeMarshalled))
		}
	})

	It("should return an error when unmarshalling data that doesn't represent a curve point", func() {
		var bs [PointSizeMarshalled]byte
		var p Point

		for i := 0; i < trials; i++ {
			_, _ = rand.Read(bs[1:])

			tail, rem, err := p.Unmarshal(bs[:], PointSize)

			if p.IsOnCurve() {
				Expect(err).ToNot(HaveOccurred())
			} else {
				Expect(err).To(HaveOccurred())
			}
			Expect(rem).To(Equal(0))
			Expect(len(tail)).To(Equal(0))
		}
	})

	//
	// Panics
	//

	It("should panic when setting bytes when the slice length is too small", func() {
		var p Point
		var bs [32]byte
		for i := 0; i < 32; i++ {
			Expect(func() { p.SetBytes(bs[:i]) }).To(Panic())
		}
	})

	It("should panic when putting bytes when the slice length is too small", func() {
		var p Point
		var bs [32]byte
		for i := 0; i < 32; i++ {
			Expect(func() { p.PutBytes(bs[:i]) }).To(Panic())
		}
	})
})

func BenchmarkAdd(b *testing.B) {
	var x, y Point

	x, y = RandomPoint(), RandomPoint()

	for i := 0; i < b.N; i++ {
		x.Add(&x, &y)
	}
}

func BenchmarkBaseExp(b *testing.B) {
	var x Point
	var scalar Fn

	scalar = RandomFn()

	for i := 0; i < b.N; i++ {
		x.BaseExp(&scalar)
	}
}
func BenchmarkScale(b *testing.B) {
	var x Point
	var scalar Fn

	x = RandomPoint()
	scalar = RandomFn()

	for i := 0; i < b.N; i++ {
		x.Scale(&x, &scalar)
	}
}