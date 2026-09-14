package identifier_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/identifier"
	"github.com/stretchr/testify/assert"
)

func TestVendorProduct_ToString(t *testing.T) {
	t.Parallel()

	p := identifier.VendorProduct{Vendor: "company-x", Product: "super_product"}
	assert.Equal(t, `"company-x":"super_product"`, p.String())

	p = identifier.VendorProduct{Vendor: "v\"1\"", Product: "p\"1\""}
	assert.Equal(t, `"v\"1\"":"p\"1\""`, p.String())
}
