package identifier

import "fmt"

// VendorProduct represents a vendor and product combination extracted from CVE data.
type VendorProduct struct {
	Vendor  string `toml:"vendor"`
	Product string `toml:"product"`
}

func (p VendorProduct) String() string {
	return fmt.Sprintf("%q:%q", p.Vendor, p.Product)
}
