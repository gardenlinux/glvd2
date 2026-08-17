package assessment

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	// bucketSize is the number of CVEs per directory bucket.
	bucketSize = 1000
)

// cveIDPattern matches a valid CVE ID and captures the year and sequence number.
var cveIDPattern = regexp.MustCompile(`^CVE-(\d{4})-(\d+)$`)

// ValidateCVEID checks whether a string is a valid CVE ID.
// Expected format: CVE-{year}-{seq} where year is exactly 4 digits and seq is a positive integer.
func ValidateCVEID(cveID string) error {
	_, _, err := parseCVEID(cveID)
	return err
}

// Path returns the filesystem path for a given CVE ID relative to the base directory.
// It follows the CVEListV5 bucketing scheme: {base}/{year}/{bucket}xxx/{cveID}.json.
func Path(baseDir, cveID string) (string, error) {
	year, seq, err := parseCVEID(cveID)
	if err != nil {
		return "", err
	}

	bucket := seq / bucketSize
	bucketDir := fmt.Sprintf("%dxxx", bucket)

	return filepath.Join(baseDir, year, bucketDir, cveID+".json"), nil
}

// parseCVEID extracts the year and sequence number from a CVE ID.
func parseCVEID(cveID string) (string, int, error) {
	matches := cveIDPattern.FindStringSubmatch(cveID)
	if matches == nil {
		return "", 0, fmt.Errorf("invalid CVE ID: %q", cveID)
	}

	year := matches[1]

	seq, err := strconv.Atoi(matches[2])
	if err != nil {
		return "", 0, fmt.Errorf("invalid CVE ID sequence: %q: %w", cveID, err)
	}
	if seq == 0 {
		return "", 0, fmt.Errorf("invalid CVE ID: %q", cveID)
	}

	return year, seq, nil
}

// FieldPath is an ordered sequence of path segments identifying a field within an Assessment
// e.g. ["releases", "2150.8.0", "auto_triage", "status"].
// Segments may contain dots; the path itself is unambiguous because each segment is stored separately.
type FieldPath []string

// String returns the dot-joined display form of the path.
// e.g. "releases.2150.8.0.auto_triage.status".
func (fp FieldPath) String() string {
	return strings.Join(fp, ".")
}

// Append returns a new FieldPath with segment added at the end.
// It always allocates to avoid aliasing bugs in loops.
func (fp FieldPath) Append(segment string) FieldPath {
	result := make(FieldPath, len(fp)+1)
	copy(result, fp)
	result[len(fp)] = segment
	return result
}
