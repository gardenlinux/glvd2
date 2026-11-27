package presentation_test

import (
	"encoding/xml"
	"errors"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func htmlElement(t *testing.T, doc *htmlNode, tag, attr, value string) *htmlNode {
	t.Helper()

	for _, node := range doc.all(tag) {
		actual, exists := node.attrs[attr]
		matchesValue := actual == value
		if attr == "class" || attr == "aria-labelledby" {
			matchesValue = slices.Contains(strings.Fields(actual), value)
		}
		if exists && matchesValue {
			return node
		}
	}

	t.Fatalf("missing %s with %s=%q", tag, attr, value)

	return nil
}

type htmlNode struct {
	name     string
	attrs    map[string]string
	children []*htmlNode
	text     string
}

// parseHTML inspects controlled renderer output, not browser HTML parsing or validity.
func parseHTML(t *testing.T, content string) *htmlNode {
	t.Helper()

	decoder := xml.NewDecoder(strings.NewReader(content))
	decoder.Strict = false
	decoder.AutoClose = xml.HTMLAutoClose
	decoder.Entity = xml.HTMLEntity

	root := &htmlNode{}
	stack := []*htmlNode{root}

	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}

		require.NoError(t, err)

		switch tok := token.(type) {
		case xml.StartElement:
			node := &htmlNode{name: tok.Name.Local, attrs: make(map[string]string)}

			for _, attr := range tok.Attr {
				node.attrs[attr.Name.Local] = attr.Value
			}

			parent := stack[len(stack)-1]
			parent.children = append(parent.children, node)

			stack = append(stack, node)
		case xml.EndElement:
			require.Greater(t, len(stack), 1)
			stack = stack[:len(stack)-1]
		case xml.CharData:
			parent := stack[len(stack)-1]
			parent.children = append(parent.children, &htmlNode{text: string(tok)})
		}
	}

	return root
}

func (n *htmlNode) all(name string) []*htmlNode {
	var nodes []*htmlNode

	if n.name != "" && (name == "" || n.name == name) {
		nodes = append(nodes, n)
	}

	for _, child := range n.children {
		nodes = append(nodes, child.all(name)...)
	}

	return nodes
}

func (n *htmlNode) content() string {
	var text strings.Builder
	text.WriteString(n.text)

	for _, child := range n.children {
		text.WriteString(child.content())
	}

	return text.String()
}

func tableWithHeaders(t *testing.T, doc *htmlNode, headers ...string) *htmlNode {
	t.Helper()

	var matches []*htmlNode

	for _, table := range doc.all("table") {
		heads := table.all("thead")
		require.Len(t, heads, 1)
		var labels []string

		for _, header := range heads[0].all("th") {
			labels = append(labels, strings.TrimSpace(header.content()))
		}

		if slices.ContainsFunc(headers, func(header string) bool { return !slices.Contains(labels, header) }) {
			continue
		}

		matches = append(matches, table)
	}
	require.Len(t, matches, 1, "table with headers %v", headers)

	return matches[0]
}

func pageTableRecords(t *testing.T, outDir, page string, headers ...string) []map[string]string {
	t.Helper()

	doc := parseHTML(t, readFile(t, filepath.Join(outDir, page)))

	return tableRecords(t, tableWithHeaders(t, doc, headers...))
}

func recordValues(records []map[string]string, field string) []string {
	values := make([]string, 0, len(records))

	for _, record := range records {
		values = append(values, record[field])
	}

	return values
}

func definition(t *testing.T, doc *htmlNode, label string) *htmlNode {
	t.Helper()

	for _, list := range doc.all("dl") {
		for _, parent := range list.all("") {
			for i, child := range parent.children {
				if child.name != "dt" || strings.TrimSpace(child.content()) != label {
					continue
				}

				for _, next := range parent.children[i+1:] {
					if next.name == "" {
						continue
					}

					require.Equal(t, "dd", next.name, label)

					return next
				}
			}
		}
	}
	t.Fatalf("missing definition for %q", label)

	return nil
}

func tableRecords(t *testing.T, table *htmlNode) []map[string]string {
	t.Helper()

	heads := table.all("thead")
	require.Len(t, heads, 1)

	headers := heads[0].all("th")

	var records []map[string]string

	for _, body := range table.all("tbody") {
		for _, row := range body.all("tr") {
			var cells []*htmlNode

			for _, child := range row.children {
				if child.name == "th" || child.name == "td" {
					cells = append(cells, child)
				}
			}

			require.Len(t, cells, len(headers))
			record := make(map[string]string, len(headers))
			for i, header := range headers {
				record[strings.TrimSpace(header.content())] = strings.TrimSpace(cells[i].content())
			}

			records = append(records, record)
		}
	}

	return records
}
