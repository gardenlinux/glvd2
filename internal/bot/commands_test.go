package bot

import (
	"errors"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

func TestParseOneLine(t *testing.T) {
	cases := []struct {
		input    string
		wantCmd  Command
		wantRO   *ReopenCommand
		wantErr  bool
	}{
		{
			input:   "/relevant confirmed reachable",
			wantCmd: TriageCommand{Status: assessment.StatusRelevant, Justification: "confirmed reachable"},
		},
		{
			input:   "/relevant",
			wantCmd: TriageCommand{Status: assessment.StatusRelevant, Justification: ""},
		},
		{
			input:   "/not-relevant false positive",
			wantCmd: TriageCommand{Status: assessment.StatusNotRelevant, Justification: "false positive"},
		},
		{
			input: "/override release=1592.15 pkg=linux status=not-affected subsystem not compiled",
			wantCmd: OverrideCommand{
				Release:       "1592.15",
				Pkg:           "linux",
				Status:        assessment.ReleaseStatusNotAffected,
				Justification: "subsystem not compiled",
			},
		},
		{
			input:   "/rescore release=1592.15 pkg=linux score=4.2 mitigated by isolation",
			wantCmd: RescoreCommand{Release: "1592.15", Pkg: "linux", Score: 4.2, Justification: "mitigated by isolation"},
		},
		{
			input:   "/notes see also CVE-2018-3646",
			wantCmd: NotesCommand{Text: "see also CVE-2018-3646"},
		},
		{
			input:  "/reopen new information",
			wantRO: &ReopenCommand{Reason: "new information"},
		},
	}

	for _, tc := range cases {
		cmd, ro, err := parseOneLine(tc.input)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseOneLine(%q): expected error, got nil", tc.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseOneLine(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if tc.wantRO != nil {
			if ro == nil || *ro != *tc.wantRO {
				t.Errorf("parseOneLine(%q): reopen got %v, want %v", tc.input, ro, tc.wantRO)
			}
		} else if cmd != tc.wantCmd {
			t.Errorf("parseOneLine(%q): got %v, want %v", tc.input, cmd, tc.wantCmd)
		}
	}
}

func TestParseOneLineErrors(t *testing.T) {
	cases := []string{
		"/rescore",
		"/rescore release=1592.15",
		"/rescore release=1592.15 pkg=linux",
		"/rescore release=1592.15 pkg=linux score=bad",
		"/override",
		"/override release=1592.15",
		"/override release=1592.15 pkg=linux",
		"/override release=1592.15 pkg=linux status=invalid",
	}

	for _, input := range cases {
		_, _, err := parseOneLine(input)
		if err == nil {
			t.Errorf("parseOneLine(%q): expected error, got nil", input)
		}
	}
}

func TestParseOneLineNotACommand(t *testing.T) {
	_, _, err := parseOneLine("just a regular comment")
	if !errors.Is(err, ErrNotACommand) {
		t.Errorf("expected ErrNotACommand, got %v", err)
	}
}

func TestParseCommandsMultiLine(t *testing.T) {
	body := `/relevant confirmed path is reachable
some extra context that is not a command
/rescore release=1592.15 pkg=linux score=3.1 mitigated
/reopen needs more investigation`

	cmds, reopen, errs := ParseCommands(body)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	// /relevant and /rescore are triage commands; /reopen is separate
	if len(cmds) != 2 { //nolint:mnd // 2 triage commands expected
		t.Fatalf("expected 2 triage commands, got %d", len(cmds))
	}
	if reopen == nil {
		t.Fatal("expected a ReopenCommand, got nil")
	}
	if reopen.Reason != "needs more investigation" {
		t.Errorf("reopen reason: got %q, want %q", reopen.Reason, "needs more investigation")
	}
}
