package debsectracker

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gardenlinux/glvd2/internal/purl"
)

// VerdictIndex is a pre-built per-(CVE, source pkg name) DST verdict index used to avoid costly DB lookups.
type VerdictIndex struct {
	// verdicts maps a CVE ID to its sid-line verdicts keyed by Debian source package name.
	verdicts map[string]map[string]Verdict
}

// NewVerdictIndex builds the index from every ingested sid-line affected package.
func (s Service) NewVerdictIndex(ctx context.Context) (*VerdictIndex, error) {
	rows, err := s.queries.ListAffectedDebianPackages(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing Debian affected packages: %w", err)
	}

	verdicts := make(map[string]map[string]Verdict)
	for _, row := range rows {
		info := ""
		if row.Info != nil {
			info = *row.Info
		}

		verdict := VerdictFromSid(row.Version, info)
		if verdict.Reason == ReasonUnknownToken {
			slog.Warn("unrecognised Debian Security Tracker sid version token",
				slog.String("cve", row.CVEID),
				slog.String("source_package_name", row.PackageName),
				slog.String("version_field", row.Version))
		}

		byPkgName := verdicts[row.CVEID]
		if byPkgName == nil {
			byPkgName = make(map[string]Verdict)
			verdicts[row.CVEID] = byPkgName
		}
		byPkgName[row.PackageName] = verdict
	}

	return &VerdictIndex{verdicts: verdicts}, nil
}

// Lookup returns the DST verdict for the (cveID, source package name)-pair,
// where the source package name is identified by a canonical identity PURL.
func (i *VerdictIndex) Lookup(cveID, sourcePURL string) (Verdict, error) {
	name, err := purl.NameOf(sourcePURL)
	if err != nil {
		return Verdict{}, fmt.Errorf("extracting source package name from PURL %q: %w", sourcePURL, err)
	}

	if v, ok := i.verdicts[cveID][name]; ok {
		return v, nil
	}

	return Verdict{Reason: ReasonNoEntry}, nil
}
