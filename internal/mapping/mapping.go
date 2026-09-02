// Package mapping correlates CVE component identifiers (CPEs, vendor-product pairs, package IDs, PURLs)
// with Debian packages that are known to be affected by those CVEs.
package mapping

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/gardenlinux/glvd2/internal/component"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/gardenlinux/glvd2/internal/sliceutil"
)

// AffectedPackageQuerier provides access to the CVE to Debian package associations.
// *repository.Queries satisfies this interface.
// Having this interface is useful for testing.
type AffectedPackageQuerier interface {
	ListAffectedDebianPackages(ctx context.Context) ([]repository.DebianTriageAffectedPackage, error)
}

// PackageCountsByID maps an identifier string (derived from VP pair, CPEs, Package IDs or PURL)
// to a set of package names with occurrence counts.
type PackageCountsByID map[string]map[string]int

// MatchingDebianPackages contains the mappings from identifiers to Debian package grouped by identifier type.
type MatchingDebianPackages struct {
	VendorProductPairs PackageCountsByID `json:"vendor_product_pairs"`
	CPEs               PackageCountsByID `json:"cpes"`
	PackageIDs         PackageCountsByID `json:"package_ids"`
	PackageURLs        PackageCountsByID `json:"package_urls"`
}

// PackageIdentifiers holds all known identifiers associated with a single Debian package.
type PackageIdentifiers struct {
	PackageURLs      []string
	PackageIDs       []string
	CPEs             []string
	VendorProductIDs []string
}

// PackageIdentifierIndex maps Debian package names to their aggregated identifiers.
type PackageIdentifierIndex map[string]PackageIdentifiers

type appendToPackageParams struct {
	PackageURLs      []string
	PackageIDs       []string
	CPEs             []string
	VendorProductIDs []string
}

func (idx PackageIdentifierIndex) appendToPackage(pkgName string, params appendToPackageParams) {
	pkg := idx[pkgName]

	if len(params.PackageURLs) > 0 {
		pkg.PackageURLs = sliceutil.Unique(append(pkg.PackageURLs, params.PackageURLs...))
	}
	if len(params.PackageIDs) > 0 {
		pkg.PackageIDs = sliceutil.Unique(append(pkg.PackageIDs, params.PackageIDs...))
	}
	if len(params.CPEs) > 0 {
		pkg.CPEs = sliceutil.Unique(append(pkg.CPEs, params.CPEs...))
	}
	if len(params.VendorProductIDs) > 0 {
		pkg.VendorProductIDs = sliceutil.Unique(append(pkg.VendorProductIDs, params.VendorProductIDs...))
	}

	idx[pkgName] = pkg
}

// addMatch increments the count for the given package name under the identifier key.
func addMatch(matches PackageCountsByID, pkgName, id string) {
	pkgCounts, ok := matches[id]
	if !ok {
		matches[id] = map[string]int{pkgName: 1}
		return
	}
	pkgCounts[pkgName]++
}

// Service performs the mapping analysis between CVE identifiers and Debian packages.
type Service struct {
	querier AffectedPackageQuerier
	filters struct {
		vendorProduct component.Filter
		cpe           component.Filter
		packageID     component.Filter
	}
}

// Option configures a Service during construction.
type Option func(*serviceConfig)

type serviceConfig struct {
	vpFilterPath  component.SafePath
	cpeFilterPath component.SafePath
	pkgFilterPath component.SafePath
}

// WithFilterPaths overrides the default filter config file paths.
func WithFilterPaths(vp, cpeFilter, pkgID component.SafePath) Option {
	return func(cfg *serviceConfig) {
		cfg.vpFilterPath = vp
		cfg.cpeFilterPath = cpeFilter
		cfg.pkgFilterPath = pkgID
	}
}

// NewService creates a new mapping Service. It loads the filter configurations from the
// default project config paths (or overridden via options) and uses querier to access
// affected package data.
func NewService(querier AffectedPackageQuerier, opts ...Option) (*Service, error) {
	cfg := serviceConfig{
		vpFilterPath:  component.DefaultVendorProductFilterConfigPath,
		cpeFilterPath: component.DefaultCPEFilterConfigPath,
		pkgFilterPath: component.DefaultPackageIDFilterConfigPath,
	}
	for _, o := range opts {
		o(&cfg)
	}

	vpFilter, err := component.NewFilter(cfg.vpFilterPath)
	if err != nil {
		return nil, fmt.Errorf("loading vendor-product filter from %q: %w", cfg.vpFilterPath, err)
	}

	cpeFilter, err := component.NewFilter(cfg.cpeFilterPath)
	if err != nil {
		return nil, fmt.Errorf("loading cpe filter from %q: %w", cfg.cpeFilterPath, err)
	}

	pkgIDFilter, err := component.NewFilter(cfg.pkgFilterPath)
	if err != nil {
		return nil, fmt.Errorf("loading package id filter from %q: %w", cfg.pkgFilterPath, err)
	}

	s := &Service{querier: querier}
	s.filters.vendorProduct = vpFilter
	s.filters.cpe = cpeFilter
	s.filters.packageID = pkgIDFilter

	return s, nil
}

// Analyze correlates CVE identifiers with affected Debian packages
// while applying filters to discard irrelevant identifiers.
// It returns the match counts per identifier type and a per-package index of all identifiers
// that contributed to that package's matches.
func (s *Service) Analyze(
	ctx context.Context,
	idsForCVEs cvelistv5.IDsForCVEs,
) (MatchingDebianPackages, PackageIdentifierIndex, error) {
	result := MatchingDebianPackages{
		VendorProductPairs: make(PackageCountsByID),
		CPEs:               make(PackageCountsByID),
		PackageIDs:         make(PackageCountsByID),
		PackageURLs:        make(PackageCountsByID),
	}
	pkgIndex := make(PackageIdentifierIndex)

	affectedPackages, err := s.querier.ListAffectedDebianPackages(ctx)
	if err != nil {
		return MatchingDebianPackages{}, nil, fmt.Errorf("listing affected debian packages: %w", err)
	}

	missingIDs := make(map[string]struct{})
	for _, affected := range affectedPackages {
		ids, ok := idsForCVEs[affected.CVEID]
		if !ok {
			missingIDs[affected.CVEID] = struct{}{}
			continue
		}

		pkgName := affected.PackageName

		s.processVendorProductPairs(pkgName, ids, result.VendorProductPairs, pkgIndex)
		s.processCPEs(pkgName, ids, result.CPEs, pkgIndex)
		s.processPackageIDs(pkgName, ids, result.PackageIDs, pkgIndex)
		s.processPackageURLs(pkgName, ids, result.PackageURLs, pkgIndex)
	}

	// Sort the slices inside the package index s.t. only real changes are shown in our audit json files.
	for _, pkgIDs := range pkgIndex {
		slices.Sort(pkgIDs.VendorProductIDs)
		slices.Sort(pkgIDs.CPEs)
		slices.Sort(pkgIDs.PackageIDs)
		slices.Sort(pkgIDs.PackageURLs)
	}

	if len(missingIDs) > 0 {
		cveIDs := make([]string, 0, len(missingIDs))
		for id := range missingIDs {
			cveIDs = append(cveIDs, id)
		}
		slices.SortFunc(cveIDs, func(a, b string) int { // descending order
			return cmp.Compare(b, a)
		})
		slog.Debug("CVEs without IDs while identifying corresponding Debian package names",
			slog.Int("count", len(cveIDs)),
			slog.Any("cve_ids", cveIDs),
		)
	}

	return result, pkgIndex, nil
}

func (s *Service) processVendorProductPairs(
	pkgName string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, vpPair := range ids.VendorProductPairs {
		if s.filters.vendorProduct.ShouldDiscard(vpPair.Vendor, vpPair.Product) {
			continue
		}

		id := vpPair.String()
		addMatch(matches, pkgName, id)
		pkgIndex.appendToPackage(pkgName, appendToPackageParams{
			VendorProductIDs: []string{id},
		})
	}
}

func (s *Service) processCPEs(
	pkgName string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, wfn := range ids.WFNs {
		if !wfn.Vendor.IsString() || !wfn.Product.IsString() {
			continue
		}

		if s.filters.cpe.ShouldDiscard(wfn.Vendor.Value, wfn.Product.Value) {
			continue
		}

		cpeStr := wfn.FormatAsCPE23String()
		addMatch(matches, pkgName, cpeStr)
		pkgIndex.appendToPackage(pkgName, appendToPackageParams{
			CPEs: []string{cpeStr},
		})
	}
}

func (s *Service) processPackageIDs(
	pkgName string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, pID := range ids.PackageIDs {
		if s.filters.packageID.ShouldDiscard(pID.CollectionURL, pID.PackageName) {
			continue
		}

		// Red Hat annotated also affected products, containers and more.
		// Hence, an easy fix seems to be to only keep the ones that contain the package name inside the packageName.
		if pID.CollectionURL == "https://access.redhat.com/downloads/content/package-browser/" ||
			pID.CollectionURL == "https://catalog.redhat.com/software/containers/" {
			if !strings.Contains(strings.ToLower(pID.PackageName), strings.ToLower(pkgName)) {
				continue
			}
		}

		pIDStr := pID.String()
		addMatch(matches, pkgName, pIDStr)
		pkgIndex.appendToPackage(pkgName, appendToPackageParams{
			PackageIDs: []string{pIDStr},
		})
	}
}

func (s *Service) processPackageURLs(
	pkgName string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, pURL := range ids.PackageURLs {
		addMatch(matches, pkgName, pURL)
		pkgIndex.appendToPackage(pkgName, appendToPackageParams{
			PackageURLs: []string{pURL},
		})
	}
}
