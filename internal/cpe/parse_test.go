package cpe_test

import (
	"errors"
	"testing"

	"github.com/gardenlinux/glvd2/internal/cpe"
)

func TestParseAutoDetect(t *testing.T) {
	t.Parallel()

	_, err := cpe.Parse("cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*")
	if err != nil {
		t.Errorf("Parse CPE v2.3 unexpected error: %v", err)
	}

	_, err = cpe.Parse("cpe:/a:foo:bar")
	if err != nil {
		t.Errorf("Parse CPE v2.2 unexpected error: %v", err)
	}

	_, err = cpe.Parse("invalid")
	if !errors.Is(err, cpe.ErrUnknownFormat) {
		t.Errorf("Parse CPE invalid: expected ErrUnknownFormat, got %v", err)
	}
}
