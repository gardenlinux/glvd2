package bot

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

// ErrNotACommand is returned by parseOneLine when the line is not a recognised command.
var ErrNotACommand = errors.New("not a command")

// CommandContext carries the per-comment metadata attached to every command.
type CommandContext struct {
	Actor        string
	IssueComment int64
	Now          time.Time
}

// Command applies a triage decision to a Record.
type Command interface {
	Apply(rec *assessment.Record, ctx CommandContext) error
}

// TriageCommand marks the CVE as relevant or not-relevant globally.
type TriageCommand struct {
	Status        assessment.TriageStatus
	Justification string
}

func (c TriageCommand) Apply(rec *assessment.Record, ctx CommandContext) error {
	entry := assessment.ManualTriageEntry{
		Status:        c.Status,
		Justification: c.Justification,
		Author:        ctx.Actor,
		At:            ctx.Now,
		IssueComment:  ctx.IssueComment,
	}
	rec.Manual.ManualTriage.Status = c.Status
	rec.Manual.ManualTriage.Justification = c.Justification
	rec.Manual.ManualTriage.History = append(rec.Manual.ManualTriage.History, entry)
	return nil
}

// OverrideCommand sets a per-release/per-package affectedness status.
type OverrideCommand struct {
	Release       string
	Pkg           string // short name or full PURL
	Status        assessment.ReleaseStatus
	Justification string
}

func (c OverrideCommand) Apply(rec *assessment.Record, ctx CommandContext) error {
	existing, commit, err := ensurePackageEntry(rec, c.Release, c.Pkg)
	if err != nil {
		return err
	}
	entry := assessment.PackageOverrideEntry{
		Status:        c.Status,
		Justification: c.Justification,
		Author:        ctx.Actor,
		At:            ctx.Now,
		IssueComment:  ctx.IssueComment,
	}
	existing.Status = c.Status
	existing.Justification = c.Justification
	existing.History = append(existing.History, entry)
	commit()
	return nil
}

// RescoreCommand sets a per-release/per-package score override.
type RescoreCommand struct {
	Release       string
	Pkg           string
	Score         float64
	Justification string
}

func (c RescoreCommand) Apply(rec *assessment.Record, ctx CommandContext) error {
	if c.Score < 0 || c.Score > 10 { //nolint:mnd // CVSS range
		return fmt.Errorf("score must be between 0.0 and 10.0, got %.1f", c.Score)
	}
	existing, commit, err := ensurePackageEntry(rec, c.Release, c.Pkg)
	if err != nil {
		return err
	}
	score := c.Score
	entry := assessment.PackageOverrideEntry{
		ScoreOverride: &score,
		Justification: c.Justification,
		Author:        ctx.Actor,
		At:            ctx.Now,
		IssueComment:  ctx.IssueComment,
	}
	existing.ScoreOverride = &score
	if c.Justification != "" {
		existing.Justification = c.Justification
	}
	existing.History = append(existing.History, entry)
	commit()
	return nil
}

// NotesCommand replaces the free-text notes on a CVE record.
type NotesCommand struct {
	Text string
}

func (c NotesCommand) Apply(rec *assessment.Record, _ CommandContext) error {
	rec.Manual.Notes = c.Text
	return nil
}

// ReopenCommand is handled at the issue level; it is not a Command and does
// not modify the assessment record. ParseCommands returns it separately.
type ReopenCommand struct {
	Reason string
}

// ApplyCommands applies every command in cmds to rec, stopping at and
// returning the first application error. It is the pure, testable core of
// the triage flow.
func ApplyCommands(rec *assessment.Record, cmds []Command, ctx CommandContext) error {
	for _, cmd := range cmds {
		if err := cmd.Apply(rec, ctx); err != nil {
			return err
		}
	}
	return nil
}

// ParseCommands scans a multi-line comment body and returns all triage
// commands, any /reopen command found, and any parse errors. Each /command
// line is parsed independently; lines not starting with "/" are ignored.
func ParseCommands(body string) (cmds []Command, reopen *ReopenCommand, errs []error) {
	for line := range strings.Lines(body) {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "/") {
			continue
		}
		cmd, ro, err := parseOneLine(trimmed)
		switch {
		case err != nil && !errors.Is(err, ErrNotACommand):
			errs = append(errs, err)
		case ro != nil:
			reopen = ro
		case cmd != nil:
			cmds = append(cmds, cmd)
		}
	}
	return cmds, reopen, errs
}

// parseOneLine parses a single slash-command line. Exactly one of cmd or
// reopen is non-nil on success; both are nil when err is ErrNotACommand.
func parseOneLine(line string) (cmd Command, reopen *ReopenCommand, err error) { //nolint:cyclop,ireturn
	switch {
	case strings.HasPrefix(line, "/relevant"):
		just := strings.TrimSpace(strings.TrimPrefix(line, "/relevant"))
		return TriageCommand{Status: assessment.StatusRelevant, Justification: just}, nil, nil

	case strings.HasPrefix(line, "/not-relevant"):
		just := strings.TrimSpace(strings.TrimPrefix(line, "/not-relevant"))
		return TriageCommand{Status: assessment.StatusNotRelevant, Justification: just}, nil, nil

	case strings.HasPrefix(line, "/override"):
		c, parseErr := parseOverrideCommand(strings.TrimSpace(strings.TrimPrefix(line, "/override")))
		return c, nil, parseErr

	case strings.HasPrefix(line, "/rescore"):
		c, parseErr := parseRescoreCommand(strings.TrimSpace(strings.TrimPrefix(line, "/rescore")))
		return c, nil, parseErr

	case strings.HasPrefix(line, "/notes"):
		text := strings.TrimSpace(strings.TrimPrefix(line, "/notes"))
		return NotesCommand{Text: text}, nil, nil

	case strings.HasPrefix(line, "/reopen"):
		reason := strings.TrimSpace(strings.TrimPrefix(line, "/reopen"))
		return nil, &ReopenCommand{Reason: reason}, nil
	}

	return nil, nil, ErrNotACommand
}

// commandsReference returns the command list shown in every issue body.
// It lives here so it stays in sync with parseOneLine above.
func commandsReference() string {
	var b strings.Builder
	b.WriteString("**Commands** (security-team only):\n")
	b.WriteString("- `/relevant [justification]` — mark CVE as relevant to Garden Linux\n")
	b.WriteString("- `/not-relevant [justification]` — mark CVE as not relevant\n")
	b.WriteString("- `/override release=<dist> pkg=<name> status=<affected|not-affected|fixed|unknown>" +
		" [justification]`\n")
	b.WriteString("- `/rescore release=<dist> pkg=<name> score=<0.0-10.0> [justification]`\n")
	b.WriteString("- `/notes <text>` — replace free-text notes\n")
	b.WriteString("- `/reopen <reason>` — reopen a closed issue\n")
	return b.String()
}

// parseFlags parses a string of "key=value" tokens separated by whitespace.
// Returns the flags map and any remaining text that follows the flags.
func parseFlags(s string) (flags map[string]string, rest string) {
	flags = make(map[string]string)
	parts := strings.Fields(s)
	i := 0
	for i < len(parts) {
		k, v, ok := strings.Cut(parts[i], "=")
		if !ok {
			break
		}
		flags[k] = v
		i++
	}
	rest = strings.TrimSpace(strings.Join(parts[i:], " "))
	return flags, rest
}

// extractReleasePkg pulls the shared release= and pkg= flags from a parsed flags map.
func extractReleasePkg(flags map[string]string, cmd string) (release, pkg string, err error) {
	release = flags["release"]
	pkg = flags["pkg"]
	if release == "" {
		return "", "", fmt.Errorf("%s requires release=<dist>", cmd)
	}
	if pkg == "" {
		return "", "", fmt.Errorf("%s requires pkg=<package>", cmd)
	}
	return release, pkg, nil
}

func parseOverrideCommand(rest string) (Command, error) { //nolint:ireturn
	flags, just := parseFlags(rest)
	release, pkg, err := extractReleasePkg(flags, "/override")
	if err != nil {
		return nil, err
	}
	statusStr := flags["status"]
	if statusStr == "" {
		return nil, errors.New("/override requires status=<affected|not-affected|fixed|unknown>")
	}

	var status assessment.ReleaseStatus
	switch assessment.ReleaseStatus(statusStr) {
	case assessment.ReleaseStatusAffected,
		assessment.ReleaseStatusNotAffected,
		assessment.ReleaseStatusFixed,
		assessment.ReleaseStatusUnknown:
		status = assessment.ReleaseStatus(statusStr)
	default:
		return nil, fmt.Errorf("/override: unknown status %q (must be affected, not-affected, fixed, or unknown)", statusStr)
	}

	return OverrideCommand{Release: release, Pkg: pkg, Status: status, Justification: just}, nil
}

func parseRescoreCommand(rest string) (Command, error) { //nolint:ireturn
	flags, just := parseFlags(rest)
	release, pkg, err := extractReleasePkg(flags, "/rescore")
	if err != nil {
		return nil, err
	}
	scoreStr := flags["score"]
	if scoreStr == "" {
		return nil, errors.New("/rescore requires score=<0.0-10.0>")
	}

	score, err := strconv.ParseFloat(scoreStr, 64)
	if err != nil {
		return nil, fmt.Errorf("/rescore: invalid score %q", scoreStr)
	}

	return RescoreCommand{Release: release, Pkg: pkg, Score: score, Justification: just}, nil
}

// ensurePackageEntry resolves the PURL for pkg in the given release, lazily
// initialises the map entries if needed, and returns the (possibly existing)
// PackageOverride value together with a commit function that writes it back.
func ensurePackageEntry(rec *assessment.Record, release, pkg string) (
	*assessment.PackageOverride, func(), error,
) {
	purl, err := resolvePURL(rec, release, pkg)
	if err != nil {
		return nil, nil, err
	}
	if purl == "" {
		return nil, nil, fmt.Errorf("unknown package %q for release %q (use full PURL or a name present in auto data)", pkg, release)
	}

	if rec.Releases == nil {
		rec.Releases = make(map[string]assessment.ReleaseDecision)
	}
	rd := rec.Releases[release]
	if rd.Manual.Packages == nil {
		rd.Manual.Packages = make(map[string]assessment.PackageOverride)
	}

	existing := rd.Manual.Packages[purl]
	commit := func() {
		rd.Manual.Packages[purl] = existing
		rec.Releases[release] = rd
	}
	return &existing, commit, nil
}

// resolvePURL returns the PURL key to use for the given pkg string and release.
// If pkg already looks like a full PURL it is returned as-is.
// Otherwise it first tries an exact match ("pkg:deb/debian/<pkg>") against the
// auto block's keys, then falls back to a suffix match ("/"+pkg). If the suffix
// match is ambiguous (multiple keys match), an error is returned.
// If no auto data exists for the release, the canonical deb PURL is synthesised.
func resolvePURL(rec *assessment.Record, release, pkg string) (string, error) {
	if strings.HasPrefix(pkg, "pkg:") {
		return pkg, nil
	}

	canonical := "pkg:deb/debian/" + pkg

	rd, ok := rec.Releases[release]
	if !ok {
		return canonical, nil
	}

	// exact match first
	if _, found := rd.Auto.Packages[canonical]; found {
		return canonical, nil
	}

	// suffix match — collect all candidates
	var matches []string
	for key := range rd.Auto.Packages {
		if strings.HasSuffix(key, "/"+pkg) {
			matches = append(matches, key)
		}
	}
	switch len(matches) {
	case 0:
		return canonical, nil
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("ambiguous package name %q matches multiple entries: %v; use a full PURL", pkg, matches)
	}
}
