// Package debmap correlates CVE component identifiers (CPEs, vendor-product pairs, package IDs, PURLs)
// with the Debian package PURLs that are known to be affected by those identifiers.
package debmap

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	"github.com/gardenlinux/glvd2/internal/configpath"
	"github.com/gardenlinux/glvd2/internal/debmap/filter"
	"github.com/gardenlinux/glvd2/internal/ingestion/cvelistv5"
	"github.com/gardenlinux/glvd2/internal/purl"
	"github.com/gardenlinux/glvd2/internal/repository"
	"github.com/gardenlinux/glvd2/internal/sliceutil"
)

// AffectedPackageQuerier provides access to the CVE to affected Debian package association.
// *repository.Queries satisfies this interface.
type AffectedPackageQuerier interface {
	ListAffectedDebianPackages(ctx context.Context) ([]repository.DebianTriageAffectedPackage, error)
}

// PackageCountsByID maps an identifier string (derived from VP pair, CPEs, Package IDs or PURL)
// to a set of identity PURLs with occurrence counts.
type PackageCountsByID map[string]map[string]int

// MatchingDebianPackages contains the mappings from component identifiers to Debian package PURLs
// grouped by identifier type.
type MatchingDebianPackages struct {
	VendorProductPairs PackageCountsByID `json:"vendor_product_pairs"`
	CPEs               PackageCountsByID `json:"cpes"`
	PackageIDs         PackageCountsByID `json:"package_ids"`
	PackageURLs        PackageCountsByID `json:"package_urls"`
}

// PackageIdentifiers holds all known component identifiers associated with a single Debian package PURL.
type PackageIdentifiers struct {
	VendorProductIDs []string
	CPEs             []string
	PackageIDs       []string
	PackageURLs      []string
}

// PackageIdentifierIndex maps Debian identity PURLs to their aggregated component identifiers.
type PackageIdentifierIndex map[string]PackageIdentifiers

type appendToPackageParams struct {
	VendorProductIDs []string
	CPEs             []string
	PackageIDs       []string
	PackageURLs      []string
}

func (idx PackageIdentifierIndex) appendToPackage(identityPURL string, params appendToPackageParams) {
	pkg := idx[identityPURL]

	if len(params.VendorProductIDs) > 0 {
		pkg.VendorProductIDs = sliceutil.Unique(append(pkg.VendorProductIDs, params.VendorProductIDs...))
	}
	if len(params.CPEs) > 0 {
		pkg.CPEs = sliceutil.Unique(append(pkg.CPEs, params.CPEs...))
	}
	if len(params.PackageIDs) > 0 {
		pkg.PackageIDs = sliceutil.Unique(append(pkg.PackageIDs, params.PackageIDs...))
	}
	if len(params.PackageURLs) > 0 {
		pkg.PackageURLs = sliceutil.Unique(append(pkg.PackageURLs, params.PackageURLs...))
	}

	idx[identityPURL] = pkg
}

// addMatch increments the count for the given identity PURL under the identifier key.
func addMatch(matches PackageCountsByID, identityPURL, id string) {
	pkgCounts, ok := matches[id]
	if !ok {
		matches[id] = map[string]int{identityPURL: 1}
		return
	}
	pkgCounts[identityPURL]++
}

// debianIdentityPURL synthesizes and canonicalizes an identity PURL for a Debian source package.
func debianIdentityPURL(pkgName string) (string, error) {
	raw := "pkg:deb/debian/" + pkgName
	canon, err := purl.Canonicalize(raw)
	if err != nil {
		return "", err
	}

	return canon, nil
}

// Service performs the mapping analysis between CVE identifiers and Debian packages.
type Service struct {
	querier AffectedPackageQuerier
	filters struct {
		vendorProduct filter.Rules
		cpe           filter.Rules
		packageID     filter.Rules
	}
}

// Option configures a Service during construction.
type Option func(*serviceConfig)

type serviceConfig struct {
	vpFilterPath  configpath.SafePath
	cpeFilterPath configpath.SafePath
	pkgFilterPath configpath.SafePath
}

// WithFilterPaths overrides the default filter config file paths.
func WithFilterPaths(vp, cpeFilter, pkgID configpath.SafePath) Option {
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
		vpFilterPath:  configpath.DefaultVendorProductFilterConfigPath,
		cpeFilterPath: configpath.DefaultCPEFilterConfigPath,
		pkgFilterPath: configpath.DefaultPackageIDFilterConfigPath,
	}
	for _, o := range opts {
		o(&cfg)
	}

	vpFilter, err := filter.New(cfg.vpFilterPath)
	if err != nil {
		return nil, fmt.Errorf("loading vendor-product filter from %q: %w", cfg.vpFilterPath, err)
	}

	cpeFilter, err := filter.New(cfg.cpeFilterPath)
	if err != nil {
		return nil, fmt.Errorf("loading cpe filter from %q: %w", cfg.cpeFilterPath, err)
	}

	pkgIDFilter, err := filter.New(cfg.pkgFilterPath)
	if err != nil {
		return nil, fmt.Errorf("loading package id filter from %q: %w", cfg.pkgFilterPath, err)
	}

	s := &Service{querier: querier}
	s.filters.vendorProduct = vpFilter
	s.filters.cpe = cpeFilter
	s.filters.packageID = pkgIDFilter

	return s, nil
}

// Analyze correlates CVE identifiers with affected Debian package PURLs while applying filters
// to discard irrelevant identifiers.
// It returns two structs one contains the match counts per identifier type for a package and
// a per-package index of all identifiers that were matched to it.
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

		identityPURL, purlErr := debianIdentityPURL(affected.PackageName)
		if purlErr != nil {
			slog.Warn("skipping package with un-canonicalizable name",
				slog.String("package_name", affected.PackageName),
				slog.String("cve_id", affected.CVEID),
				slog.String("error_msg", purlErr.Error()),
			)
			continue
		}

		s.processVendorProductPairs(identityPURL, ids, result.VendorProductPairs, pkgIndex)
		s.processCPEs(identityPURL, ids, result.CPEs, pkgIndex)
		s.processPackageIDs(identityPURL, affected.PackageName, ids, result.PackageIDs, pkgIndex)
		s.processPackageURLs(identityPURL, ids, result.PackageURLs, pkgIndex)
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
	identityPURL string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, vpPair := range ids.VendorProductPairs {
		if s.filters.vendorProduct.ShouldDiscard(vpPair.Vendor, vpPair.Product) {
			continue
		}

		id := vpPair.String()
		addMatch(matches, identityPURL, id)
		pkgIndex.appendToPackage(identityPURL, appendToPackageParams{
			VendorProductIDs: []string{id},
		})
	}
}

func (s *Service) processCPEs(
	identityPURL string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, wfn := range ids.WFNs {
		vendor, product, ok := wfn.VendorProduct()
		if !ok {
			continue
		}

		if s.filters.cpe.ShouldDiscard(vendor, product) {
			continue
		}

		cpeStr := wfn.FormatAsCPE23String()
		addMatch(matches, identityPURL, cpeStr)
		pkgIndex.appendToPackage(identityPURL, appendToPackageParams{
			CPEs: []string{cpeStr},
		})
	}
}

func (s *Service) processPackageIDs(
	identityPURL string,
	pkgName string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, pID := range ids.PackageIDs {
		if s.filters.packageID.ShouldDiscard(pID.CollectionURL, pID.PackageName) {
			continue
		}

		// Red Hat annotated also affected products, containers and more, which creates a lot of noise.
		// An easy workaround seems to be to only keep the ones that contain the package name inside the packageName.
		if pID.CollectionURL == "https://access.redhat.com/downloads/content/package-browser/" ||
			pID.CollectionURL == "https://catalog.redhat.com/software/containers/" {
			if !strings.Contains(strings.ToLower(pID.PackageName), strings.ToLower(pkgName)) {
				continue
			}
		}

		pIDStr := pID.String()
		addMatch(matches, identityPURL, pIDStr)
		pkgIndex.appendToPackage(identityPURL, appendToPackageParams{
			PackageIDs: []string{pIDStr},
		})
	}
}

func (s *Service) processPackageURLs(
	identityPURL string,
	ids *cvelistv5.Identifiers,
	matches PackageCountsByID,
	pkgIndex PackageIdentifierIndex,
) {
	for _, p := range ids.PackageURLs {
		addMatch(matches, identityPURL, p)
		pkgIndex.appendToPackage(identityPURL, appendToPackageParams{
			PackageURLs: []string{p},
		})
	}
}
