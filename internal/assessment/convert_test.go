package assessment_test

import (
	"testing"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordFromCVEV5(t *testing.T) {
	t.Parallel()

	published := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	cve := &cve_v5.CVEV5{}
	cve.Metadata.ID = "CVE-2026-1234"
	cve.Metadata.DatePublished = published
	cve.Containers.CNAContainer.Descriptions = []cve_v5.Description{
		{Lang: "de", Value: "Speicherüberlauf in foo"},
		{Lang: "en", Value: "buffer overflow in foo"},
	}

	before := time.Now().UTC()
	rec := assessment.RecordFromCVEV5(cve)
	after := time.Now().UTC()

	assert.Equal(t, "CVE-2026-1234", rec.ID)
	assert.Equal(t, "buffer overflow in foo", rec.Upstream.Description)
	assert.Equal(t, published, rec.Upstream.PublishedAt)

	// FirstSeenAt is seeded to the current time on the incoming record.
	require.False(t, rec.Meta.FirstSeenAt.IsZero(), "FirstSeenAt must be seeded")
	assert.False(t, rec.Meta.FirstSeenAt.Before(before))
	assert.False(t, rec.Meta.FirstSeenAt.After(after))
}

func TestRecordFromCVEV5_DescriptionFallback(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		descriptions []cve_v5.Description
		want         string
	}{
		{
			name:         "no descriptions",
			descriptions: nil,
			want:         "",
		},
		{
			name:         "no english description; falls back to first",
			descriptions: []cve_v5.Description{{Lang: "de", Value: "de description"}},
			want:         "de description",
		},
		{
			name: "prefers en over others",
			descriptions: []cve_v5.Description{
				{Lang: "de", Value: "de description"},
				{Lang: "en", Value: "en description"},
			},
			want: "en description",
		},
		{
			name: "us before en in list (take whatever comes first)",
			descriptions: []cve_v5.Description{
				{Lang: "de", Value: "de description"},
				{Lang: "en-US", Value: "us description"},
				{Lang: "en", Value: "en description"},
			},
			want: "us description",
		},
		{
			name: "en before us in list (take whatever comes first)",
			descriptions: []cve_v5.Description{
				{Lang: "de", Value: "de description"},
				{Lang: "en", Value: "en description"},
				{Lang: "en-US", Value: "us description"},
			},
			want: "en description",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cve := &cve_v5.CVEV5{}
			cve.Metadata.ID = "CVE-2026-0001"
			cve.Containers.CNAContainer.Descriptions = tt.descriptions

			rec := assessment.RecordFromCVEV5(cve)
			assert.Equal(t, tt.want, rec.Upstream.Description)
		})
	}
}
