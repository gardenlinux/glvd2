package repos_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/repos"
	"github.com/stretchr/testify/assert"
)

func TestAnalyzeComments(t *testing.T) {
	t.Parallel()

	prepare_source := `# apt_src libgcrypt20
apply_patches
#version_suffix="gl3"`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepare_source, metadata)
	assert.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.False(t, metadata.UpstreamPatches)
	assert.True(t, metadata.GlPatches)
}

func TestAnalyze1(t *testing.T) {
	t.Parallel()

	prepare_source := `git_src -b debian/openssl-3.5.5-1 https://salsa.debian.org/debian/openssl.git
import_upstream_patches
apply_patches patches-debian
version_suffix="gl21"`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepare_source, metadata)
	assert.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.True(t, metadata.GitSrc)
	assert.True(t, metadata.SalsaSrc)
	assert.True(t, metadata.DebianPatches)
	assert.True(t, metadata.UpstreamPatches)
}

func TestAnalyze2(t *testing.T) {
	t.Parallel()

	prepare_source := `version_orig=2.20250213-11
version="2:${version_orig}"
version_suffix=gl1

# there are no tags or branches used in this repo to pin the version
git_src_commit "39488fe01d9de5175c5ccccfcac30b667965d701" "https://salsa.debian.org/selinux-team/refpolicy.git"
import_upstream_patches`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepare_source, metadata)
	assert.NoError(t, err)

	assert.True(t, metadata.GitSrc)
	assert.True(t, metadata.SalsaSrc)
	assert.True(t, metadata.UpstreamPatches)
}

func TestAnalyze3(t *testing.T) {
	t.Parallel()

	prepare_source := `UPSTREAM_VERSION="v7.2.0"

upstream=$(mktemp -d)
git clone -b "$UPSTREAM_VERSION" --depth=1 https://github.com/canonical/checkbox.git "$upstream" 
pushd "$upstream"
git sparse-checkout set providers/gpgpu 
popd

import_src "$upstream/providers/gpgpu"

version=7.2.0
version_suffix="gl0"

apply_patches`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepare_source, metadata)
	assert.NoError(t, err)

	assert.True(t, metadata.GitSrc)
	assert.True(t, metadata.GlPatches)
}

func TestAnalyze4(t *testing.T) {
	t.Parallel()

	prepare_source := `apt-get install -y --no-install-recommends curl ca-certificates

curl -sSLf https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.12.tar.xz \
| xz -d \
| tee "$dir/orig.tar" \
| tar --extract --strip-components 1 --directory "$dir/src"

salsadir="$(mktemp -d)"
git clone --depth 1 --branch 3.8.12-3 https://salsa.debian.org/gnutls-team/gnutls.git "$salsadir"
mv "$salsadir/debian" "$dir/src"
rm -rf "$salsadir"

apply_patches
version_suffix="gl3~bp1877"`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepare_source, metadata)
	assert.NoError(t, err)

	assert.True(t, metadata.GitSrc)
	assert.True(t, metadata.UpstreamSrc)
	assert.True(t, metadata.GlPatches)
	assert.True(t, metadata.SalsaSrc)
}

func TestGetPackageNameFromBranch(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "gnutls", repos.ExtractPackageName("bp-package-gnutls"))
	assert.Equal(t, "gnutls", repos.ExtractPackageName("package-gnutls"))
}
