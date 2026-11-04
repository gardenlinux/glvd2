package bot_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/bot"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssessmentPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cveID string
		want  string
	}{
		{"CVE-2024-1234", "data/2024/1xxx/CVE-2024-1234.json"},
		{"CVE-2024-12345", "data/2024/12xxx/CVE-2024-12345.json"},
		{"CVE-2008-3595", "data/2008/3xxx/CVE-2008-3595.json"},
		{"CVE-2024-999", "data/2024/0xxx/CVE-2024-999.json"},
		{"CVE-2024-1", "data/2024/0xxx/CVE-2024-1.json"},
	}

	for _, tc := range cases {
		t.Run(tc.cveID, func(t *testing.T) {
			t.Parallel()
			path, err := assessment.Path("data", tc.cveID)
			require.NoError(t, err, "cveID=%s", tc.cveID)
			assert.Equal(t, tc.want, path, "cveID=%s", tc.cveID)
		})
	}
}

func TestAssessmentPath_InvalidID(t *testing.T) {
	t.Parallel()
	_, err := assessment.Path("data", "not-a-cve")
	assert.Error(t, err)
}

func TestIsValidCVEID(t *testing.T) {
	t.Parallel()
	valid := []string{"CVE-2024-1234", "CVE-2008-3595", "CVE-2024-999999"}
	for _, id := range valid {
		assert.True(t, bot.IsValidCVEID(id), "expected valid: %s", id)
	}

	invalid := []string{"cve-2024-1234", "CVE-24-1234", "CVE-2024", "BDSA-2024-1234", ""}
	for _, id := range invalid {
		assert.False(t, bot.IsValidCVEID(id), "expected invalid: %s", id)
	}
}
