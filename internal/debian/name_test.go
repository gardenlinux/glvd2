package debian_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/debian"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePackageName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{name: "simple", in: "openssl"},
		{name: "with digits", in: "libc6"},
		{name: "with plus", in: "g++"},
		{name: "with period and minus", in: "gcc-12.1"},
		{name: "leading digit", in: "0ad"},
		{name: "empty", in: "", wantErr: debian.ErrEmptyName},
		{name: "only whitespace", in: " ", wantErr: debian.ErrInvalidName},
		{name: "only whitespaces", in: "  ", wantErr: debian.ErrInvalidName},
		{name: "single char", in: "a", wantErr: debian.ErrInvalidName},
		{name: "leading minus", in: "-foo", wantErr: debian.ErrInvalidName},
		{name: "uppercase", in: "OpenSSL", wantErr: debian.ErrInvalidName},
		{name: "underscore", in: "bad_name", wantErr: debian.ErrInvalidName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := debian.ValidatePackageName(tt.in)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}
			assert.NoError(t, err)
		})
	}
}
