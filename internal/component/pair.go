package component

import "fmt"

// Pair represents a vendor and product combination extracted from CVE data.
type Pair struct {
	Vendor  string
	Product string
}

func (p Pair) String() string {
	return fmt.Sprintf("%q:%q", p.Vendor, p.Product)
}
