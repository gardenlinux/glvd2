package presentation

import (
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

type packageLink struct {
	Name              string
	SourcePackagePURL string
	URL               string
}

type externalLink struct {
	Label string
	URL   string
}

type cveAffectednessSummary struct {
	Releases    []cveReleaseRow
	Counts      []countRow
	NeedsReview int
}

func buildCVEAffectednessSummary(releases []cveReleaseRow) cveAffectednessSummary {
	summary := cveAffectednessSummary{}
	counts := make(map[string]int)

	for _, rel := range releases {
		if rel.Historical {
			continue
		}

		summary.Releases = append(summary.Releases, rel)

		counts[rel.Affectedness]++

		if rel.NeedsReview {
			summary.NeedsReview++
		}
	}

	for _, status := range []assessment.ReleaseStatus{
		assessment.ReleaseStatusAffected,
		assessment.ReleaseStatusFixed,
		assessment.ReleaseStatusNotAffected,
		assessment.ReleaseStatusUnknown,
	} {
		summary.Counts = append(summary.Counts, countRow{Label: string(status), Count: counts[string(status)]})
	}

	return summary
}

func cveExternalSources(id string) []externalLink {
	return []externalLink{
		{Label: "Debian Security Tracker", URL: "https://security-tracker.debian.org/tracker/" + url.PathEscape(id)},
		{Label: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + url.PathEscape(id)},
		{Label: "GitHub Advisory Database", URL: "https://github.com/advisories?query=" + url.QueryEscape(id)},
	}
}

func relevanceExplanation(rec assessment.Record) string {
	if !rec.Manual.ManualTriage.IsEmpty() {
		status := string(rec.Manual.ManualTriage.Status)

		decision := "This CVE is " + strings.ReplaceAll(
			status,
			"-",
			" ",
		) + " to Garden Linux based on a manual decision."

		if why := strings.TrimSpace(rec.Manual.ManualTriage.Justification); why != "" {
			return decision + " " + why
		}

		return decision + " No justification is recorded."
	}

	switch rec.Screening.AutoTriage.Reason {
	case assessment.TriageReasonAffectsDebianPackage:
		return "This CVE is relevant to Garden Linux, because it concerns a Debian source package included in Garden Linux."
	case assessment.TriageReasonAffectsGardenLinuxPackage:
		return "This CVE is relevant to Garden Linux, because it concerns a Garden Linux specific source package."
	case assessment.TriageReasonAffectsVendoredDependency:
		return "This CVE is relevant to Garden Linux, because " +
			"it concerns a component embedded in a package included in Garden Linux."
	case assessment.TriageReasonRejectedUpstream:
		return "This CVE is not relevant to Garden Linux, because its upstream publisher has rejected the record."
	case assessment.TriageReasonDebianNotForUs:
		return "This CVE is not relevant to Garden Linux, because " +
			"the Debian Security Tracker marks it as outside Debian's scope."
	case assessment.TriageReasonDebianPackageNotShipped:
		return "This CVE is not relevant to Garden Linux, because the package it concerns is not included in Garden Linux."
	case assessment.TriageReasonAwaitingDebian:
		return "Relevance to Garden Linux is undecided while screening awaits a Debian decision."
	default:
		return "Relevance to Garden Linux is undecided, because no recognized screening decision is recorded."
	}
}

// cvePackageURLs only links packages this record guarantees will have a page, regardless of walk order.
func (rr *renderRun) cvePackageURLs(rec assessment.Record) (map[string]string, error) {
	urls := make(map[string]string)

	if rec.GetGlobalStatus() != assessment.StatusRelevant {
		return urls, nil
	}

	for _, version := range slices.Sorted(maps.Keys(rec.Releases)) {
		if _, maintained := rr.agg.maintainedSet[version]; !maintained {
			continue
		}

		for _, identity := range slices.Sorted(maps.Keys(rec.Releases[version].EffectiveReasons())) {
			name, _, nameErr := packageNameNamespace(identity)
			if nameErr != nil {
				return nil, nameErr
			}

			if _, exists := urls[name]; exists {
				continue
			}

			packageURL, err := rr.r.urls.Package(name)
			if err != nil {
				return nil, err
			}

			urls[name] = packageURL
		}
	}

	return urls, nil
}

func packageLinks(srcPkgPURLs []string, urls map[string]string) ([]packageLink, error) {
	links := make([]packageLink, 0, len(srcPkgPURLs))

	for _, purl := range slices.Sorted(slices.Values(srcPkgPURLs)) {
		name, _, err := packageNameNamespace(purl)
		if err != nil {
			return nil, err
		}

		links = append(links, packageLink{Name: name, SourcePackagePURL: purl, URL: urls[name]})
	}

	return links, nil
}

func releaseExplanation(rd assessment.ReleaseDecision) string {
	if len(rd.EffectiveReasons()) == 0 {
		return "No contributing source packages are recorded for this release."
	}

	for _, override := range rd.Manual.Packages {
		if !override.IsEmpty() {
			// A manual status maps to a representative reason, not evidence of a version comparison.
			return explainTerm(string(rd.CompositeStatus())) + " This result includes manual package decisions."
		}
	}

	return explainTerm(string(rd.CompositeReason()))
}

func explainBasis(basis string) string {
	switch basis {
	case "fix-evidence":
		return "A patch naming this CVE is included in the build."
	case "concrete-fix-version":
		return "A fixed version from Debian bounds the vulnerable range."
	case "not-affected":
		return "Debian has declared the package not affected."
	case "debian-unfixed":
		return "Debian records the issue without a fixed version."
	case "upstream-unfixed":
		return "Upstream reports affected versions without a bounding fix."
	case "upstream-derived":
		return "The vulnerable range comes from upstream version information."
	case "no-authority":
		return "No vulnerability authority provided a conclusive result."
	case "eval-undecidable":
		return "The shipped version could not be compared with the vulnerable range."
	case "vendored-deferred":
		return "Assessment of the embedded dependency requires human review."
	default:
		return displayLabel(basis)
	}
}

// explainTerm expands assessment terms without changing their meaning or stored representation.
func explainTerm(term string) string {
	switch term {
	case "affected":
		return "At least one source package is assessed as affected."
	case "fixed":
		return "At least one source package is assessed as fixed, and none are assessed as affected or unknown."
	case "not-affected":
		return "No contributing source package is assessed as affected or unknown."
	case "unknown":
		return "At least one source package has an inconclusive assessment."
	case "affects-debian-package":
		return "This CVE concerns a source package included in Garden Linux."
	case "affects-gardenlinux-package":
		return "This CVE concerns a Garden Linux specific source package."
	case "affects-vendored-dependency":
		return "This CVE concerns a component embedded in a package included in Garden Linux."
	case "rejected-upstream":
		return "The CVE record has been rejected by its upstream publisher."
	case "debian-not-for-us":
		return "The Debian Security Tracker marks this CVE as outside Debian's scope."
	case "debian-package-not-shipped":
		return "The package this CVE concerns is not included in Garden Linux."
	case "awaiting-debian":
		return "A decision from the Debian Security Tracker is still pending."
	case "package-not-shipped":
		return "The source package is not shipped in this release."
	case "declared-not-affected":
		return "A vulnerability authority has declared the source package not affected."
	case "version-fixed":
		return "The shipped version is assessed as fixed based on patch or version evidence."
	case "version-vulnerable":
		return "The shipped version falls within the recorded vulnerable range."
	case "affected-escalated":
		return "The package is presumed affected, but no fixed version bounds the finding. Human review is needed."
	case "unknown-escalated":
		return "The available evidence is insufficient to determine affectedness. Human review is needed."
	default:
		return displayLabel(term)
	}
}
