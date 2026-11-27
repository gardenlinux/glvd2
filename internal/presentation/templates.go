package presentation

import (
	"embed"
	"fmt"
	"html/template"
)

//go:embed templates/*.html assets/*
var templateFS embed.FS

func loadTemplates() (map[string]*template.Template, error) {
	pages := []string{
		"overview",
		"releases",
		"statistics",
		"cves",
		"undecided",
		"release",
		"flavor",
		"cve",
		"packages",
		"package",
	}
	templates := make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		tmpl, err := template.New("base").Funcs(template.FuncMap{
			"label":        displayLabel,
			"explain":      explainTerm,
			"explainBasis": explainBasis,
			"num":          formatInteger,
			"inlineAsset":  inlineAsset,
		}).ParseFS(templateFS, "templates/base.html", "templates/"+page+".html")
		if err != nil {
			return nil, fmt.Errorf("parsing %s template: %w", page, err)
		}
		templates[page] = tmpl
	}

	return templates, nil
}

// inlineAsset returns an embedded asset's contents for inlining into a page.
func inlineAsset(path string) (template.JS, error) {
	data, err := templateFS.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading inline asset %q: %w", path, err)
	}

	// The content is an embedded asset under our control, not user input, so
	// bypassing auto-escaping to inline it verbatim is safe.
	return template.JS(data), nil //nolint:gosec // trusted embedded asset
}
