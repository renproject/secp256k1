package secp256k1_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestSecp256k1(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Secp256k1 Suite")
}
