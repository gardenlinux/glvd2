package packages

import cdx "github.com/CycloneDX/cyclonedx-go"

// dependencyGraph is the parsed SBOM dependency graph:
// each component bom-ref mapped to the bom-refs it directly depends on (CycloneDX `dependsOn`).
type dependencyGraph struct {
	edges map[string][]string
}

// buildDependencyGraph indexes the SBOM dependency edges by source bom-ref.
func buildDependencyGraph(deps []cdx.Dependency) dependencyGraph {
	g := dependencyGraph{edges: make(map[string][]string, len(deps))}
	for _, dep := range deps {
		if dep.Dependencies == nil {
			continue
		}
		g.edges[dep.Ref] = append(g.edges[dep.Ref], (*dep.Dependencies)...)
	}

	return g
}

// dependsOn returns the bom-refs the given ref directly depends on.
func (g dependencyGraph) dependsOn(ref string) []string {
	return g.edges[ref]
}
