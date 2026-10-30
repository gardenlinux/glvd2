package bot

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

// ErrNotACommand is returned by ParseCommand when the line is not a recognised command.
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

// RelevantCommand marks the CVE as globally relevant to Garden Linux.
type RelevantCommand struct {
	Justification string
}

func (c RelevantCommand) Apply(rec *assessment.Record, ctx CommandContext) error {
	entry := assessment.ManualTriageEntry{
		Status:        assessment.StatusRelevant,
		Justification: c.Justification,
		Author:        ctx.Actor,
		At:            ctx.Now,
		IssueComment:  ctx.IssueComment,
	}
	rec.Manual.ManualTriage.Status = assessment.StatusRelevant
	rec.Manual.ManualTriage.Justification = c.Justification
	rec.Manual.ManualTriage.History = append(rec.Manual.ManualTriage.History, entry)
	return nil
}

// NotRelevantCommand marks the CVE as not relevant to Garden Linux.
type NotRelevantCommand struct {
	Justification string
}

func (c NotRelevantCommand) Apply(rec *assessment.Record, ctx CommandContext) error {
	entry := assessment.ManualTriageEntry{
		Status:        assessment.StatusNotRelevant,
		Justification: c.Justification,
		Author:        ctx.Actor,
		At:            ctx.Now,
		IssueComment:  ctx.IssueComment,
	}
	rec.Manual.ManualTriage.Status = assessment.StatusNotRelevant
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
	purl := resolvePURL(rec, c.Release, c.Pkg)
	if purl == "" {
		return fmt.Errorf("unknown package %q for release %q (use full PURL or a name present in auto data)", c.Pkg, c.Release)
	}

	if rec.Releases == nil {
		rec.Releases = make(map[string]assessment.ReleaseDecision)
	}
	rd := rec.Releases[c.Release]
	if rd.Manual.Packages == nil {
		rd.Manual.Packages = make(map[string]assessment.PackageOverride)
	}

	existing := rd.Manual.Packages[purl]
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
	rd.Manual.Packages[purl] = existing
	rec.Releases[c.Release] = rd
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

	purl := resolvePURL(rec, c.Release, c.Pkg)
	if purl == "" {
		return fmt.Errorf("unknown package %q for release %q (use full PURL or a name present in auto data)", c.Pkg, c.Release)
	}

	if rec.Releases == nil {
		rec.Releases = make(map[string]assessment.ReleaseDecision)
	}
	rd := rec.Releases[c.Release]
	if rd.Manual.Packages == nil {
		rd.Manual.Packages = make(map[string]assessment.PackageOverride)
	}

	existing := rd.Manual.Packages[purl]
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
	rd.Manual.Packages[purl] = existing
	rec.Releases[c.Release] = rd
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

// ReopenCommand is handled at the issue level; Apply is a no-op.
type ReopenCommand struct {
	Reason string
}

func (c ReopenCommand) Apply(_ *assessment.Record, _ CommandContext) error { return nil }

// ParseCommand parses a single line from an issue comment into a Command.
// Returns ErrNotACommand if the line is not a recognised command.
func ParseCommand(line string) (Command, error) { //nolint:ireturn,cyclop // interface intentional, switch is fine
	line = strings.TrimSpace(line)

	switch {
	case strings.HasPrefix(line, "/relevant"):
		just := strings.TrimSpace(strings.TrimPrefix(line, "/relevant"))
		return RelevantCommand{Justification: just}, nil

	case strings.HasPrefix(line, "/not-relevant"):
		just := strings.TrimSpace(strings.TrimPrefix(line, "/not-relevant"))
		return NotRelevantCommand{Justification: just}, nil

	case strings.HasPrefix(line, "/override"):
		return parseOverrideCommand(strings.TrimSpace(strings.TrimPrefix(line, "/override")))

	case strings.HasPrefix(line, "/rescore"):
		return parseRescoreCommand(strings.TrimSpace(strings.TrimPrefix(line, "/rescore")))

	case strings.HasPrefix(line, "/notes"):
		text := strings.TrimSpace(strings.TrimPrefix(line, "/notes"))
		return NotesCommand{Text: text}, nil

	case strings.HasPrefix(line, "/reopen"):
		reason := strings.TrimSpace(strings.TrimPrefix(line, "/reopen"))
		return ReopenCommand{Reason: reason}, nil
	}

	return nil, ErrNotACommand
}

// ParseCommands scans a multi-line comment body and returns all recognised commands.
// Lines after the first command line that don't start with "/" are treated as
// continuation justification for the preceding command.
func ParseCommands(body string) ([]Command, []error) {
	var cmds []Command
	var errs []error

	for line := range strings.Lines(body) {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "/") {
			continue
		}
		cmd, err := ParseCommand(trimmed)
		if errors.Is(err, ErrNotACommand) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cmds = append(cmds, cmd)
	}

	return cmds, errs
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

func parseOverrideCommand(rest string) (Command, error) {
	flags, just := parseFlags(rest)

	release := flags["release"]
	pkg := flags["pkg"]
	statusStr := flags["status"]

	if release == "" {
		return nil, errors.New("/override requires release=<dist>")
	}
	if pkg == "" {
		return nil, errors.New("/override requires pkg=<package>")
	}
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

func parseRescoreCommand(rest string) (Command, error) {
	flags, just := parseFlags(rest)

	release := flags["release"]
	pkg := flags["pkg"]
	scoreStr := flags["score"]

	if release == "" {
		return nil, errors.New("/rescore requires release=<dist>")
	}
	if pkg == "" {
		return nil, errors.New("/rescore requires pkg=<package>")
	}
	if scoreStr == "" {
		return nil, errors.New("/rescore requires score=<0.0-10.0>")
	}

	score, err := strconv.ParseFloat(scoreStr, 64)
	if err != nil {
		return nil, fmt.Errorf("/rescore: invalid score %q", scoreStr)
	}

	return RescoreCommand{Release: release, Pkg: pkg, Score: score, Justification: just}, nil
}

// resolvePURL returns the PURL key to use for the given pkg string and release.
// If pkg already looks like a full PURL it is returned as-is.
// Otherwise it tries to find a suffix match in the auto block's package keys.
func resolvePURL(rec *assessment.Record, release, pkg string) string {
	if strings.HasPrefix(pkg, "pkg:") {
		return pkg
	}

	rd, ok := rec.Releases[release]
	if !ok {
		// release not yet in file — synthesise the canonical deb PURL
		return "pkg:deb/debian/" + pkg
	}

	for key := range rd.Auto.Packages {
		if strings.HasSuffix(key, "/"+pkg) {
			return key
		}
	}

	// not found in auto — synthesise
	return "pkg:deb/debian/" + pkg
}
