package cvelistv5

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gardenlinux/glvd2/internal/component"
	"github.com/gardenlinux/glvd2/internal/config"
	"github.com/gardenlinux/glvd2/internal/cpe"
	"github.com/gardenlinux/glvd2/internal/model/cve_v5"
	"github.com/gardenlinux/glvd2/internal/sliceutil"
)

type Service struct {
	cfg *config.AppConfig
}

func NewService(cfg *config.AppConfig) *Service {
	return &Service{
		cfg: cfg,
	}
}

func (s Service) parseJSONFile(fp string) (*cve_v5.CVEV5, error) {
	fp = filepath.Clean(fp)
	if !strings.HasPrefix(fp, filepath.Clean(s.cfg.CVEListV5SubRepoPath)) {
		slog.Error("Prefix does not match",
			slog.String("filepath", fp), slog.String("expectedPrefix", s.cfg.CVEListV5SubRepoPath))
		return nil, errors.New("unsafe file path used")
	}
	jsonFile, err := os.Open(fp)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := jsonFile.Close(); closeErr != nil {
			slog.Error("Error while closing JSON file",
				slog.Any("error", err))
		}
	}()

	bytes, err := io.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var cveV5 cve_v5.CVEV5
	err = json.Unmarshal(bytes, &cveV5)
	if err != nil {
		enrichedErr := fmt.Errorf("parsing JSON file \"%s\" failed: %w", fp, err)
		return nil, enrichedErr
	}

	return &cveV5, nil
}

func (s Service) parseWorker(
	ctx context.Context,
	cancel context.CancelFunc,
	pathQueue <-chan string,
	cveCh chan<- *cve_v5.CVEV5,
	ec chan error,
) {
	for path := range pathQueue {
		select {
		case <-ctx.Done():
			return
		default:
		}

		cveV5, err := s.parseJSONFile(path)
		if err != nil {
			cancel()
			select {
			case ec <- err:
			default: // ignore additional errors
			}
			return
		}

		select {
		case cveCh <- cveV5:
		case <-ctx.Done():
			return
		}
	}
}

// ReceiveCVEs parses the CVEs folder.
func (s Service) ReceiveCVEs(ctx context.Context) (<-chan *cve_v5.CVEV5, <-chan error) {
	cveBufferSize := 64
	ch := make(chan *cve_v5.CVEV5, cveBufferSize)
	ec := make(chan error, 1)

	ctx, cancel := context.WithCancel(ctx)

	go func() {
		defer close(ec)
		defer close(ch)
		defer cancel()

		pathQueueSize := 32
		pathQueue := make(chan string, pathQueueSize)
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				s.parseWorker(ctx, cancel, pathQueue, ch, ec)
			})
		}

		err := filepath.WalkDir(s.cfg.CVEListV5SubRepoPath, func(fp string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			// stop the walk if the context got canceled
			if err = ctx.Err(); err != nil {
				return err
			}

			if !d.IsDir() && strings.HasPrefix(filepath.Base(fp), "CVE-") && filepath.Ext(fp) == ".json" {
				select {
				case pathQueue <- fp:
				case <-ctx.Done():
					return ctx.Err()
				}
			}

			return nil
		})
		if err != nil {
			cancel()
			ec <- err
		}
		close(pathQueue)

		wg.Wait()
	}()

	return ch, ec
}

type PackageIdentifier struct {
	CollectionURL string
	PackageName   string
}

func (pID PackageIdentifier) String() string {
	return fmt.Sprintf("%q:%q", pID.CollectionURL, pID.PackageName)
}

type Identifiers struct {
	VendorProductPairs []component.Pair    // fallback of using a combination of the vendor and product as id
	WFNs               cpe.UniqueWFNMap    // CPE identifiers used in the CVE
	PackageIDs         []PackageIdentifier // was introduced before packageURL
	PackageURLs        []string            // newest format to identify a package
}

// merge incorporates all identifiers from other into ids, deduplicating the result.
func (ids *Identifiers) merge(other Identifiers) {
	if len(other.VendorProductPairs) > 0 {
		ids.VendorProductPairs = sliceutil.Unique(append(ids.VendorProductPairs, other.VendorProductPairs...))
	}

	if len(other.WFNs) > 0 {
		if ids.WFNs == nil {
			ids.WFNs = maps.Clone(other.WFNs)
		} else {
			ids.WFNs = ids.WFNs.Union(other.WFNs)
		}
	}

	if len(other.PackageIDs) > 0 {
		ids.PackageIDs = sliceutil.Unique(append(ids.PackageIDs, other.PackageIDs...))
	}

	if len(other.PackageURLs) > 0 {
		ids.PackageURLs = sliceutil.Unique(append(ids.PackageURLs, other.PackageURLs...))
	}
}

func (ids *Identifiers) isEmpty() bool {
	return len(ids.VendorProductPairs) == 0 && len(ids.WFNs) == 0 &&
		len(ids.PackageIDs) == 0 && len(ids.PackageURLs) == 0
}

type IDsForCVEs map[string]*Identifiers

func normalizeVendorProductString(str string) string {
	return strings.ToLower(strings.TrimSpace(str))
}

func getVendorProductPairIfPossible(rawVendor, rawProduct string) *component.Pair {
	vendor := normalizeVendorProductString(rawVendor)
	product := normalizeVendorProductString(rawProduct)

	// A lot of CVEs have "n/a" for the affected vendor and product entry.
	// But there are also a lot of CVEs where vendor is "n/a" but product is not.
	// Hence, we have to keep these special vendor "n/a" pairs to increase our mapping potential.
	const notAvailable = "n/a"
	if vendor == "" || product == "" || product == notAvailable {
		return nil
	}

	return &component.Pair{Vendor: vendor, Product: product}
}

func processAffectedEntries(idsForCVEs IDsForCVEs, cveID string, affected []cve_v5.Affected) {
	newIDs := Identifiers{
		VendorProductPairs: []component.Pair{},
		WFNs:               cpe.NewUniqueWFNMapFrom([]cpe.WFN{}),
		PackageURLs:        []string{},
		PackageIDs:         []PackageIdentifier{},
	}

	for _, entry := range affected {
		vpPair := getVendorProductPairIfPossible(entry.Vendor, entry.Product)
		if vpPair != nil {
			newIDs.VendorProductPairs = append(newIDs.VendorProductPairs, *vpPair)
		}

		for _, cpeStr := range entry.CPEs {
			wfn, err := convertCPEStringToNormalizedWFN(cveID, cpeStr)
			if err != nil {
				continue
			}
			newIDs.WFNs.Add(wfn)
		}

		if entry.PackageURL != "" {
			newIDs.PackageURLs = append(newIDs.PackageURLs, entry.PackageURL)
		}

		if entry.CollectionURL != "" && entry.PackageName != "" {
			newIDs.PackageIDs = append(newIDs.PackageIDs, PackageIdentifier{
				CollectionURL: entry.CollectionURL,
				PackageName:   entry.PackageName,
			})
		}
	}

	if newIDs.isEmpty() {
		return
	}

	existing, ok := idsForCVEs[cveID]
	if !ok {
		existing = &Identifiers{WFNs: make(cpe.UniqueWFNMap)}
		idsForCVEs[cveID] = existing
	}
	existing.merge(newIDs) // merge always deduplicates, which is needed since newIDs is on purpose not
}

func processApplicabilityStatements(
	idsForCVEs IDsForCVEs,
	cveID string,
	statements []cve_v5.CPEApplicabilityStatement,
) {
	for _, st := range statements {
		for _, n := range st.Nodes {
			for _, m := range n.CPEMatch {
				wfn, err := convertCPEStringToNormalizedWFN(cveID, m.Criteria)
				if err != nil {
					continue
				}

				if _, ok := idsForCVEs[cveID]; !ok {
					idsForCVEs[cveID] = &Identifiers{
						WFNs: cpe.NewUniqueWFNMapFrom([]cpe.WFN{wfn}),
					}
				} else {
					idsForCVEs[cveID].WFNs.Add(wfn)
				}
			}
		}
	}
}

func convertCPEStringToNormalizedWFN(cveID, cpeStr string) (cpe.WFN, error) {
	wfn, err := cpe.Parse(cpeStr)
	if err != nil {
		slog.Warn("Invalid CPE format; skipping CPE for mapping analysis",
			slog.String("cve_id", cveID),
			slog.String("cpe_string", cpeStr),
			slog.Any("error", err))
		return cpe.WFN{}, err
	}

	// normalize the CPE in WFN form
	wfn.KeepOnlyVendorAndProduct()

	return wfn, nil
}

func (s Service) GetIDsForCVEs(ctx context.Context) (IDsForCVEs, error) {
	slog.Info("Extracting the CPEs and other software identifiers for the CVEs from CVE List V5")

	const expectedNumberOfCVEsWithIdentifiers = 500_000
	idsForCVEs := make(IDsForCVEs, expectedNumberOfCVEsWithIdentifiers)

	// Reading the data here only for the CPEs, since we need them when we actually process the CVEs.
	// Storing multiple gigabytes of CVEs in the CVE V5 format the whole run of the program in memory is not an option.
	// Also for now we try to avoid storing them inside the internal sqlite, since this would be extra effort and
	// we do not need most of the data.
	resCh, errCh := s.ReceiveCVEs(ctx)
	processed := 0
	// Use || (not &&) to ensure both channels are fully drained.
	// A closed buffered channel still delivers its queued items before signalling ok=false.
	for resCh != nil || errCh != nil {
		select {
		case cve, ok := <-resCh:
			if !ok {
				resCh = nil
				continue
			}

			processed++
			if processed%50_000 == 0 {
				slog.Info("ID extraction progress",
					slog.Int("processed", processed),
					slog.Int("cves_with_identifiers", len(idsForCVEs)),
				)
			}

			cveID := cve.Metadata.ID

			processAffectedEntries(idsForCVEs, cveID, cve.Containers.CNAContainer.Affected)
			processApplicabilityStatements(idsForCVEs, cveID, cve.Containers.CNAContainer.CPEApplicability)

			for _, adp := range cve.Containers.ADPContainer {
				processAffectedEntries(idsForCVEs, cveID, adp.Affected)
				processApplicabilityStatements(idsForCVEs, cveID, adp.CPEApplicability)
			}

		case cveErr, ok := <-errCh:
			if !ok {
				errCh = nil
				continue
			}
			if cveErr != nil {
				slog.Error("Parsing the CVEs from CVEListV5 failed", slog.Any("error", cveErr))
				return nil, cveErr
			}
		}
	}

	slog.Info(
		"Finished extracting the IDs from CVEs of the CVE List V5",
		slog.Int("processed", processed),
		slog.Int("cves_with_identifiers", len(idsForCVEs)),
	)

	return idsForCVEs, nil
}
