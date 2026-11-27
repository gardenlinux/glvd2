// Package presentation renders a hosting-independent static site from a run's persisted assessment records
// and the flavor inventory the pipeline run built.
package presentation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/gardenlinux/flavorinventory"
)

const (
	dirPermissions   = 0o755
	filePermissions  = 0o644
	progressInterval = 50_000
)

// RenderConfig holds the renderer settings.
type RenderConfig struct {
	// OutDir is the parent under which each run's unique output directory is created.
	OutDir string
	// BuildSHA is the VCS revision of the glvd2 binary.
	// An empty string is accepted and rendered as "unknown".
	BuildSHA string
}

// RenderMetrics reports what a render produced.
type RenderMetrics struct {
	Duration   time.Duration
	HTMLPages  int
	HTMLBytes  int64
	AssetFiles int
	AssetBytes int64
}

// Result is the outcome of a successful render.
type Result struct {
	OutDir  string
	Metrics RenderMetrics
}

// Renderer writes a self-contained static site to a unique per-run directory.
type Renderer struct {
	cfg       RenderConfig
	urls      SiteURLs
	templates map[string]*template.Template
}

func NewRenderer(cfg RenderConfig) (*Renderer, error) {
	if cfg.OutDir == "" {
		return nil, errors.New("output directory must not be empty")
	}

	templates, err := loadTemplates()
	if err != nil {
		return nil, fmt.Errorf("loading templates: %w", err)
	}

	return &Renderer{cfg: cfg, templates: templates}, nil
}

// Render leaves failed partial output in place for debugging but does not report it as deployable.
func (r *Renderer) Render(
	ctx context.Context,
	src RecordWalker,
	inv flavorinventory.Inventory,
	releases []string,
) (Result, error) {
	start := time.Now()

	if err := os.MkdirAll(r.cfg.OutDir, dirPermissions); err != nil {
		return Result{}, fmt.Errorf("creating output directory %q: %w", r.cfg.OutDir, err)
	}

	prefix := start.UTC().Format("20060102-150405") + "-"
	outDir, err := os.MkdirTemp(r.cfg.OutDir, prefix)
	if err != nil {
		return Result{}, fmt.Errorf("creating run output directory: %w", err)
	}

	// MkdirTemp creates with mode 0700, so widen to dirPermissions.
	if err = os.Chmod(outDir, dirPermissions); err != nil {
		return Result{}, fmt.Errorf("setting run output directory permissions: %w", err)
	}

	sha := r.cfg.BuildSHA
	if sha == "" {
		sha = "unknown"
	}

	rr := &renderRun{
		r:           r,
		outDir:      outDir,
		inv:         inv,
		agg:         newAggregator(inv, releases),
		buildSHA:    sha,
		generatedAt: start.UTC().Format("2006-01-02 15:04 UTC"),
	}
	if err = rr.run(ctx, src); err != nil {
		slog.Error("site render failed; partial output is not deployable",
			slog.String("partialOutDir", outDir),
			slog.Any("error", err),
		)
		return Result{}, err
	}

	rr.metrics.Duration = time.Since(start)
	rr.logSummary()

	return Result{OutDir: outDir, Metrics: rr.metrics}, nil
}

// renderRun holds the mutable state of one render. It is not safe for concurrent use.
type renderRun struct {
	r           *Renderer
	outDir      string
	inv         flavorinventory.Inventory
	agg         *aggregator
	metrics     RenderMetrics
	processed   int
	buildSHA    string
	generatedAt string
}

func (rr *renderRun) run(ctx context.Context, src RecordWalker) error {
	if err := rr.walkAssessments(ctx, src); err != nil {
		return fmt.Errorf("walking assessments: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	releases := rr.agg.finish()
	if err := rr.writeReleasesPage(releases); err != nil {
		return fmt.Errorf("writing releases index: %w", err)
	}
	for _, rel := range releases {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := rr.writeReleasePage(ctx, rel); err != nil {
			return fmt.Errorf("writing release %q: %w", rel.Version, err)
		}
	}

	if err := rr.writeOverviewPage(releases); err != nil {
		return fmt.Errorf("writing index: %w", err)
	}

	if err := rr.writeStatisticsPage(); err != nil {
		return fmt.Errorf("writing statistics: %w", err)
	}

	if err := rr.writeCVELanding(); err != nil {
		return fmt.Errorf("writing CVE landing: %w", err)
	}

	if err := rr.writeUndecidedList(ctx); err != nil {
		return fmt.Errorf("writing undecided CVE list: %w", err)
	}

	packages, pkgErr := rr.agg.finishPackages()
	if pkgErr != nil {
		return fmt.Errorf("finishing packages: %w", pkgErr)
	}
	if err := rr.writePackagesPage(packages); err != nil {
		return fmt.Errorf("writing packages index: %w", err)
	}
	for _, pkg := range packages {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := rr.writePackagePage(pkg); err != nil {
			return fmt.Errorf("writing package %q: %w", pkg.Name, err)
		}
	}

	if err := rr.writeFooterMetaJS(); err != nil {
		return fmt.Errorf("writing footer meta script: %w", err)
	}

	return rr.writeAssets()
}

// jsStringLiteral renders v as a safely escaped JavaScript string literal for
// embedding in generated script source.
func jsStringLiteral(v any) ([]byte, error) {
	// JSON string syntax is a subset of JS string syntax, and encoding/json escapes quotes,
	// backslashes, control characters and HTML-sensitive runes, so the result is a valid,
	// injection-safe literal.
	return json.Marshal(v)
}

// writeFooterMetaJS adds a mechanism that dynamically adds the timestamp and versions SHAs
// to the footer of the static HTML files via JS in the browser s.t. all of these files do not have
// to change with every new run because of them.
func (rr *renderRun) writeFooterMetaJS() error {
	generatedAt, err := jsStringLiteral(rr.generatedAt)
	if err != nil {
		return fmt.Errorf("encoding generated-at: %w", err)
	}

	short, err := jsStringLiteral(shortSHA(rr.buildSHA))
	if err != nil {
		return fmt.Errorf("encoding short SHA: %w", err)
	}

	full, err := jsStringLiteral(rr.buildSHA)
	if err != nil {
		return fmt.Errorf("encoding full SHA: %w", err)
	}

	js := fmt.Sprintf(
		"(function(){"+
			"var el=document.getElementById('run-meta');"+
			"if(!el)return;"+
			"var g=document.getElementById('run-meta-generated-at');"+
			"var s=document.getElementById('run-meta-sha');"+
			"if(g)g.textContent=%s;"+
			"if(s){s.textContent=%s;s.title=%s;}"+
			"el.hidden=false;"+
			"}());",
		generatedAt, short, full,
	)

	data := []byte(js)
	if err = rr.writeFile("assets/footer-meta.js", data); err != nil {
		return err
	}
	rr.metrics.AssetFiles++
	rr.metrics.AssetBytes += int64(len(data))
	return nil
}

func (rr *renderRun) walkAssessments(ctx context.Context, src RecordWalker) error {
	return src.Walk(ctx, func(rec assessment.Record) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		if err := rr.agg.add(rec); err != nil {
			return fmt.Errorf("aggregating %s: %w", rec.ID, err)
		}

		if err := rr.writeCVEPage(rec); err != nil {
			return fmt.Errorf("writing CVE %s: %w", rec.ID, err)
		}

		rr.processed++
		if rr.processed%progressInterval == 0 {
			slog.Info("rendering progress", slog.Int("processed", rr.processed))
		}

		return nil
	})
}

func (rr *renderRun) logSummary() {
	c := rr.agg.counts

	slog.Info("site rendered",
		slog.String("outDir", rr.outDir),
		slog.Duration("duration", rr.metrics.Duration),
		slog.Int("cves", c.Total),
		slog.Int("relevant", c.Relevant),
		slog.Int("notRelevant", c.NotRelevant),
		slog.Int("undecided", c.Undecided),
		slog.Int("htmlPages", rr.metrics.HTMLPages),
		slog.Int64("htmlBytes", rr.metrics.HTMLBytes),
		slog.Int("assetFiles", rr.metrics.AssetFiles),
		slog.Int64("assetBytes", rr.metrics.AssetBytes),
	)
}

func (rr *renderRun) writePage(pagePath, templateName string, data pageData) error {
	data.setPath(pagePath)

	var buf bytes.Buffer

	if err := rr.r.templates[templateName].ExecuteTemplate(&buf, "base", data); err != nil {
		return fmt.Errorf("executing template %q for %q: %w", templateName, pagePath, err)
	}

	if err := rr.writeFile(pagePath, buf.Bytes()); err != nil {
		return err
	}

	rr.metrics.HTMLPages++
	rr.metrics.HTMLBytes += int64(buf.Len())

	return nil
}

func (rr *renderRun) writeAssets() error {
	entries, err := fs.ReadDir(templateFS, "assets")
	if err != nil {
		return fmt.Errorf("reading assets: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		assetPath := "assets/" + entry.Name()
		data, readErr := templateFS.ReadFile(assetPath)
		if readErr != nil {
			return fmt.Errorf("reading asset %q: %w", assetPath, readErr)
		}

		if writeErr := rr.writeFile(assetPath, data); writeErr != nil {
			return writeErr
		}

		rr.metrics.AssetFiles++
		rr.metrics.AssetBytes += int64(len(data))
	}

	return nil
}

func (rr *renderRun) writeFile(artifactPath string, data []byte) error {
	outPath := filepath.Join(rr.outDir, filepath.FromSlash(artifactPath))

	if err := os.MkdirAll(filepath.Dir(outPath), dirPermissions); err != nil {
		return fmt.Errorf("creating directory for %q: %w", outPath, err)
	}

	if err := os.WriteFile(outPath, data, filePermissions); err != nil {
		return fmt.Errorf("writing %q: %w", outPath, err)
	}

	return nil
}
