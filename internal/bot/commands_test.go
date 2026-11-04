package bot_test

import (
	"errors"
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
	"github.com/gardenlinux/glvd2/internal/bot"
)

func TestParseOneLine(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input   string
		wantCmd bot.Command
		wantRO  *bot.ReopenCommand
		wantErr bool
	}{
		{
			input:   "/relevant confirmed reachable",
			wantCmd: bot.TriageCommand{Status: assessment.StatusRelevant, Justification: "confirmed reachable"},
		},
		{
			input:   "/relevant",
			wantCmd: bot.TriageCommand{Status: assessment.StatusRelevant, Justification: ""},
		},
		{
			input:   "/not-relevant false positive",
			wantCmd: bot.TriageCommand{Status: assessment.StatusNotRelevant, Justification: "false positive"},
		},
		{
			input: "/override release=1592.15 pkg=linux status=not-affected subsystem not compiled",
			wantCmd: bot.OverrideCommand{
				Release:       "1592.15",
				Pkg:           "linux",
				Status:        assessment.ReleaseStatusNotAffected,
				Justification: "subsystem not compiled",
			},
		},
		{
			input: "/rescore release=1592.15 pkg=linux score=4.2 mitigated by isolation",
			wantCmd: bot.RescoreCommand{
				Release:       "1592.15",
				Pkg:           "linux",
				Score:         4.2,
				Justification: "mitigated by isolation",
			},
		},
		{
			input:   "/notes see also CVE-2018-3646",
			wantCmd: bot.NotesCommand{Text: "see also CVE-2018-3646"},
		},
		{
			input:  "/reopen new information",
			wantRO: &bot.ReopenCommand{Reason: "new information"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			cmd, ro, err := bot.ParseOneLine(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("parseOneLine(%q): expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Errorf("parseOneLine(%q): unexpected error: %v", tc.input, err)
				return
			}
			if tc.wantRO != nil {
				if ro == nil || *ro != *tc.wantRO {
					t.Errorf("parseOneLine(%q): reopen got %v, want %v", tc.input, ro, tc.wantRO)
				}
			} else if cmd != tc.wantCmd {
				t.Errorf("parseOneLine(%q): got %v, want %v", tc.input, cmd, tc.wantCmd)
			}
		})
	}
}

func TestParseOneLineErrors(t *testing.T) {
	t.Parallel()
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
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			_, _, err := bot.ParseOneLine(input)
			if err == nil {
				t.Errorf("parseOneLine(%q): expected error, got nil", input)
			}
		})
	}
}

func TestParseOneLineNotACommand(t *testing.T) {
	t.Parallel()
	_, _, err := bot.ParseOneLine("just a regular comment")
	if !errors.Is(err, bot.ErrNotACommand) {
		t.Errorf("expected ErrNotACommand, got %v", err)
	}
}

func TestParseCommandsMultiLine(t *testing.T) {
	t.Parallel()
	body := `/relevant confirmed path is reachable
some extra context that is not a command
/rescore release=1592.15 pkg=linux score=3.1 mitigated
/reopen needs more investigation`

	cmds, reopen, errs := bot.ParseCommands(body)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(cmds) != 2 {
		t.Fatalf("expected 2 triage commands, got %d", len(cmds))
	}
	if reopen == nil {
		t.Fatal("expected a ReopenCommand, got nil")
	}
	if reopen.Reason != "needs more investigation" {
		t.Errorf("reopen reason: got %q, want %q", reopen.Reason, "needs more investigation")
	}
}
