package presentation_test

import (
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func collectIDs(t *testing.T, file string, node *htmlNode, ids map[string]bool) {
	t.Helper()

	if id := node.attrs["id"]; id != "" {
		assert.False(t, ids[id], "%s has duplicate ID %s", file, id)
		ids[id] = true
	}

	for _, child := range node.children {
		collectIDs(t, file, child, ids)
	}
}

func checkLinks(t *testing.T, file string, node *htmlNode, tree map[string]string, ids map[string]map[string]bool) {
	t.Helper()

	for _, attr := range []string{"href", "src"} {
		raw, exists := node.attrs[attr]

		if !exists {
			continue
		}

		link, err := url.Parse(raw)
		require.NoError(t, err, "%s in %s", raw, file)

		if link.IsAbs() {
			assert.Equal(t, "a", node.name, "external runtime dependency in %s", file)
			assert.Contains(t, []string{"https", "http"}, link.Scheme)
			continue
		}

		assert.Empty(t, link.Host, file)
		assert.False(t, strings.HasPrefix(link.Path, "/"), "absolute link %s in %s", raw, file)

		target := file
		if link.Path != "" {
			target = path.Clean(path.Join(path.Dir(file), link.Path))
		}

		assert.False(t, strings.HasPrefix(target, "../"), "link escapes artifact in %s", file)
		assert.Contains(t, tree, target, "broken link %s in %s", raw, file)

		if link.Fragment != "" {
			assert.True(
				t,
				ids[target][link.Fragment],
				"missing fragment %s in %s linked from %s",
				link.Fragment,
				target,
				file,
			)
		}
	}

	for _, child := range node.children {
		checkLinks(t, file, child, tree, ids)
	}
}

func TestArtifact_LinksAndMetrics(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{
		"1877.26": {
			"aws":      {"glibc"},
			"barebone": {"openssl"},
		},
	})
	rec := relevantRecord("CVE-2024-0001", map[string]assessment.ReleaseDecision{
		"1877.26": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
		"184.0": autoDecision(nil),
	})
	rec.Upstream.References = []string{"https://example.org/advisory#details"}

	res := render(
		t,
		inv,
		[]string{"1877.26", "2000.1"},
		rec,
		notRelevantRecord("CVE-2024-0002", nil),
		assessment.Record{ID: "CVE-2024-0003"},
	)

	tree := collectTree(t, res.OutDir)

	docs := make(map[string]*htmlNode)
	ids := make(map[string]map[string]bool)

	for file, content := range tree {
		if !strings.HasSuffix(file, ".html") {
			continue
		}

		doc := parseHTML(t, content)
		docs[file] = doc

		ids[file] = make(map[string]bool)
		collectIDs(t, file, doc, ids[file])
	}

	for file, doc := range docs {
		checkLinks(t, file, doc, tree, ids)
	}

	assert.Len(t, docs, res.Metrics.HTMLPages)

	var assetFiles int
	var assetBytes, htmlBytes int64

	for file, content := range tree {
		if strings.HasSuffix(file, ".html") {
			htmlBytes += int64(len(content))
		}
		if strings.HasPrefix(file, "assets/") {
			assetFiles++
			assetBytes += int64(len(content))
		}
	}

	assert.Equal(t, assetFiles, res.Metrics.AssetFiles)
	assert.Equal(t, assetBytes, res.Metrics.AssetBytes)
	assert.Equal(t, htmlBytes, res.Metrics.HTMLBytes)
}

func TestArtifact_RelativeLinksAndReleaseAnchors(t *testing.T) {
	t.Parallel()

	inv := inventory(t, map[string]map[string][]string{
		"1877.26": {"kvm": {"glibc"}},
	})
	rec := relevantRecord("CVE-2024-0001", map[string]assessment.ReleaseDecision{
		"1877.26": autoDecision(map[string]assessment.PackageStatus{
			glID("glibc"): autoPkg(assessment.ReleaseReasonVersionVulnerable),
		}),
	})

	res := render(t, inv, []string{"1877.26"}, rec)

	for _, tc := range []struct{ page, tag, target string }{
		{"index.html", "a", "releases/1877.26/index.html"},
		{releasePath("1877.26"), "a", "../../cves/CVE-2024-0001/index.html"},
		{flavorPath("1877.26", "kvm"), "link", "../../../../assets/site.css"},
		{flavorPath("1877.26", "kvm"), "a", "../../../../cves/CVE-2024-0001/index.html#release-1877.26"},
		{packagePath("glibc"), "a", "../../cves/CVE-2024-0001/index.html#release-1877.26"},
	} {
		doc := parseHTML(t, readFile(t, filepath.Join(res.OutDir, tc.page)))
		htmlElement(t, doc, tc.tag, "href", tc.target)
	}

	doc := parseHTML(t, readCVEPage(t, res.OutDir, rec.ID))
	htmlElement(t, doc, "", "id", "release-1877.26")
	htmlElement(t, doc, "a", "href", "#release-1877.26")
}
