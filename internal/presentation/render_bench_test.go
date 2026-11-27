package presentation_test

import (
	"strconv"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/presentation"
)

// BenchmarkRender measures the full render pipeline on a synthetic dataset.
func BenchmarkRender(b *testing.B) {
	const (
		numReleases       = 3
		numCVEs           = 500
		flavorsPerRelease = 4
	)

	flavors := []string{"aws", "gcp", "azure", "metal"}
	sources := []string{"glibc", "openssl", "curl", "zlib"}

	spec := make(map[string]map[string][]string, numReleases)
	maintained := make([]string, 0, numReleases)

	for i := range numReleases {
		rel := "1877." + strconv.Itoa(i)

		maintained = append(maintained, rel)

		spec[rel] = make(map[string][]string, flavorsPerRelease)

		for _, fl := range flavors {
			spec[rel][fl] = sources
		}
	}

	var recs []assessment.Record
	for i := 1; i <= numCVEs; i++ {
		rd := make(map[string]assessment.ReleaseDecision, numReleases)

		for j := range numReleases {
			rel := "1877." + strconv.Itoa(j)

			pkgs := make(map[string]assessment.PackageStatus, len(sources))
			for _, src := range sources {
				pkgs[glID(src)] = autoPkg(assessment.ReleaseReasonVersionVulnerable)
			}

			rd[rel] = autoDecision(pkgs)
		}
		recs = append(recs, relevantRecord(idForSeq(i), rd))
	}

	invB := inventory(b, spec)

	b.ResetTimer()

	for range b.N {
		s, err := presentation.NewRenderer(presentation.RenderConfig{OutDir: b.TempDir()})
		if err != nil {
			b.Fatal(err)
		}

		if _, err = s.Render(b.Context(), sliceSource(recs), invB, maintained); err != nil {
			b.Fatal(err)
		}
	}
}
