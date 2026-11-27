package presentation_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCVE_UntrustedTextRemainsText(t *testing.T) {
	t.Parallel()

	const payload = `<script>alert('payload')</script>"><img src=x onerror=alert('payload')>`

	for _, tc := range []struct {
		name string
		set  func(*assessment.Record)
	}{
		{"upstream description", func(rec *assessment.Record) { rec.Upstream.Description = payload }},
		{"upstream CWE", func(rec *assessment.Record) { rec.Upstream.CWEs = []string{payload} }},
		{"manual notes", func(rec *assessment.Record) { rec.Manual.Notes = payload }},
		{"manual relevance justification", func(rec *assessment.Record) {
			rec.Manual.ManualTriage = assessment.ManualTriage{Status: assessment.StatusRelevant, Justification: payload}
		}},
		{"manual package justification", func(rec *assessment.Record) {
			rec.Releases = map[string]assessment.ReleaseDecision{
				"1877.26": decision(nil, map[string]assessment.PackageOverride{
					glID("glibc"): {Status: assessment.ReleaseStatusAffected, Justification: payload},
				}),
			}
		}},
		{"evidence explanation", func(rec *assessment.Record) {
			rec.Releases = map[string]assessment.ReleaseDecision{
				"1877.26": autoDecision(map[string]assessment.PackageStatus{
					glID("glibc"): {Reason: assessment.ReleaseReasonUnknownEscalated, BasisWhy: payload},
				}),
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			rec := relevantRecord("CVE-2024-1001", nil)

			tc.set(&rec)

			res := render(t, inventory(t, nil), []string{"1877.26"}, rec)

			doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))
			main := htmlElement(t, doc, "main", "id", "main")
			assert.Contains(t, main.content(), payload, "text must be preserved, not stripped")
			assertNoInjectedMarkup(t, main)
		})
	}
}

func TestCVE_ReferenceURLsCannotInjectMarkupOrScriptSchemes(t *testing.T) {
	t.Parallel()

	rec := relevantRecord("CVE-2024-1001", nil)
	rec.Upstream.References = []string{
		`https://example.org/a"><script>alert('ref')</script>`,
		`javascript:alert('ref')`,
	}
	res := render(t, inventory(t, nil), nil, rec)

	doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))
	references := htmlElement(t, doc, "", "aria-labelledby", "references-heading")
	assertNoInjectedMarkup(t, references)

	links := references.all("a")
	require.Len(t, links, len(rec.Upstream.References))

	labels := make([]string, 0, len(links))
	for _, link := range links {
		labels = append(labels, link.content())
		target, err := url.Parse(link.attrs["href"])
		require.NoError(t, err)
		assert.Contains(t, []string{"", "http", "https"}, strings.ToLower(target.Scheme))
	}
	assert.ElementsMatch(t, rec.Upstream.References, labels)
}

func assertNoInjectedMarkup(t *testing.T, node *htmlNode) {
	t.Helper()

	assert.Empty(t, node.all("script"))
	assert.Empty(t, node.all("img"))

	for _, element := range node.all("") {
		for attr := range element.attrs {
			assert.False(t, strings.HasPrefix(strings.ToLower(attr), "on"), "injected event attribute %s", attr)
		}
	}
}
