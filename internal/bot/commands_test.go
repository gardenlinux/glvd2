package bot

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/assessment"
)

func TestParseCommand(t *testing.T) {
	cases := []struct {
		input string
		want  Command
	}{
		{
			"/relevant confirmed reachable",
			RelevantCommand{Justification: "confirmed reachable"},
		},
		{
			"/relevant",
			RelevantCommand{Justification: ""},
		},
		{
			"/not-relevant false positive",
			NotRelevantCommand{Justification: "false positive"},
		},
		{
			"/override release=1592.15 pkg=linux status=not-affected subsystem not compiled",
			OverrideCommand{Release: "1592.15", Pkg: "linux", Status: assessment.ReleaseStatusNotAffected, Justification: "subsystem not compiled"},
		},
		{
			"/rescore release=1592.15 pkg=linux score=4.2 mitigated by isolation",
			RescoreCommand{Release: "1592.15", Pkg: "linux", Score: 4.2, Justification: "mitigated by isolation"},
		},
		{
			"/notes see also CVE-2018-3646",
			NotesCommand{Text: "see also CVE-2018-3646"},
		},
		{
			"/reopen new information",
			ReopenCommand{Reason: "new information"},
		},
	}

	for _, tc := range cases {
		got, err := ParseCommand(tc.input)
		if err != nil {
			t.Errorf("ParseCommand(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseCommand(%q): got %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestParseCommandErrors(t *testing.T) {
	cases := []struct {
		input string
	}{
		{"/rescore"},
		{"/rescore release=1592.15"},
		{"/rescore release=1592.15 pkg=linux"},
		{"/rescore release=1592.15 pkg=linux score=bad"},
		{"/override"},
		{"/override release=1592.15"},
		{"/override release=1592.15 pkg=linux"},
		{"/override release=1592.15 pkg=linux status=invalid"},
	}

	for _, tc := range cases {
		_, err := ParseCommand(tc.input)
		if err == nil {
			t.Errorf("ParseCommand(%q): expected error, got nil", tc.input)
		}
	}
}

func TestParseCommandsMultiLine(t *testing.T) {
	body := `/relevant confirmed path is reachable
some extra context that is not a command
/rescore release=1592.15 pkg=linux score=3.1 mitigated
/reopen needs more investigation`

	cmds, errs := ParseCommands(body)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(cmds) != 3 { //nolint:mnd // 3 commands expected
		t.Fatalf("expected 3 commands, got %d", len(cmds))
	}
}

func TestParseCommandNotACommand(t *testing.T) {
	_, err := ParseCommand("just a regular comment")
	if err != ErrNotACommand {
		t.Errorf("expected ErrNotACommand, got %v", err)
	}
}
