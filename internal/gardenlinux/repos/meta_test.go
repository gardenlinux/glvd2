package repos_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/repos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeComments(t *testing.T) {
	t.Parallel()

	prepareSource := `# apt_src libgcrypt20
apply_patches
#version_suffix="gl3"`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepareSource, metadata)
	require.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.False(t, metadata.DebianSrc)
	assert.False(t, metadata.SalsaSrc)
	assert.False(t, metadata.UpstreamSrc)

	assert.False(t, metadata.DebianPatches)
	assert.True(t, metadata.GlPatches)
	assert.False(t, metadata.UpstreamPatches)
}

func TestAnalyze1(t *testing.T) {
	t.Parallel()

	prepareSource := `git_src -b debian/openssl-3.5.5-1 https://salsa.debian.org/debian/openssl.git
import_upstream_patches
apply_patches patches-debian
version_suffix="gl21"`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepareSource, metadata)
	require.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.False(t, metadata.DebianSrc)
	assert.True(t, metadata.SalsaSrc)
	assert.False(t, metadata.UpstreamSrc)

	assert.True(t, metadata.DebianPatches)
	assert.False(t, metadata.GlPatches)
	assert.True(t, metadata.UpstreamPatches)
}

func TestAnalyze2(t *testing.T) {
	t.Parallel()

	prepareSource := `version_orig=2.20250213-11
version="2:${version_orig}"
version_suffix=gl1

# there are no tags or branches used in this repo to pin the version
git_src_commit "39488fe01d9de5175c5ccccfcac30b667965d701" "https://salsa.debian.org/selinux-team/refpolicy.git"
import_upstream_patches`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata, err := repos.AnalyzePrepareSource(prepareSource, metadata)
	require.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.False(t, metadata.DebianSrc)
	assert.True(t, metadata.SalsaSrc)
	assert.False(t, metadata.UpstreamSrc)

	assert.False(t, metadata.DebianPatches)
	assert.False(t, metadata.GlPatches)
	assert.True(t, metadata.UpstreamPatches)
}

func TestAnalyze3(t *testing.T) {
	t.Parallel()

	prepareSource := `UPSTREAM_VERSION="v7.2.0"

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
	metadata.Branch = "package-checkbox-provider-gpgpu"
	metadata, err := repos.AnalyzePrepareSource(prepareSource, metadata)
	require.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.False(t, metadata.DebianSrc)
	assert.False(t, metadata.SalsaSrc)
	assert.True(t, metadata.UpstreamSrc)

	assert.False(t, metadata.DebianPatches)
	assert.True(t, metadata.GlPatches)
	assert.False(t, metadata.UpstreamPatches)
}

func TestAnalyze4(t *testing.T) {
	t.Parallel()

	prepareSource := `apt-get install -y --no-install-recommends curl ca-certificates

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
	metadata.Branch = "package-gnutls"

	metadata, err := repos.AnalyzePrepareSource(prepareSource, metadata)
	require.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.False(t, metadata.DebianSrc)
	assert.True(t, metadata.SalsaSrc)
	assert.True(t, metadata.UpstreamSrc)

	assert.False(t, metadata.DebianPatches)
	assert.True(t, metadata.GlPatches)
	assert.False(t, metadata.UpstreamPatches)
}

func TestAnalyze5(t *testing.T) {
	t.Parallel()

	prepareSource := `version_orig=20260522.00
plugin_manager_commit=c98709762f0de7e6b9fda26ec4dbd9dd3c43237a

plugin_manager_workdir="$(mktemp -d)"

git clone --depth=1 --revision="$plugin_manager_commit" https://github.com/GoogleCloudPlatform/google-guest-agent.git "$plugin_manager_workdir"
rm -rf "$plugin_manager_workdir/.git"


# Clone upstream repository
workdir="$(mktemp -d)"

git clone --depth 1 --recurse-submodules --branch "${version_orig}" https://github.com/GoogleCloudPlatform/guest-agent.git "$workdir"

pushd "$workdir"

# Fix upstream Debian package definition
mv ./packaging/debian ./

latest_commit_message="$(git log -1 --pretty="format:%s" ./google_guest_agent)"
latest_commit_datetime="$(git log -1 --pretty="format:%aD" ./google_guest_agent)"

tee ./debian/changelog << EOF
google-guest-agent (1:${version_orig}) stable; urgency=medium

  * $latest_commit_message
  * Detailed changelog can be found at https://github.com/GoogleCloudPlatform/guest-agent/commits/${version_orig}

 -- $maintainer <$email>  $latest_commit_datetime
EOF

echo "3.0 (native)" > ./debian/source/format

cp -r -T "$plugin_manager_workdir" google-guest-agent

# Cleanup
rm -rf ./.git
rm -rf ./packaging

popd

# Import modified upstream source distribution
import_src "$workdir"

rm -rf "$workdir"`

	var metadata *repos.RepositoryMetadata
	metadata = &repos.RepositoryMetadata{}
	metadata.Branch = "package-google-guest-agent"

	metadata, err := repos.AnalyzePrepareSource(prepareSource, metadata)
	require.NoError(t, err)

	assert.False(t, metadata.AptSrc)
	assert.False(t, metadata.DebianSrc)
	assert.False(t, metadata.SalsaSrc)
	assert.True(t, metadata.UpstreamSrc)

	assert.False(t, metadata.DebianPatches)
	assert.False(t, metadata.GlPatches)
	assert.False(t, metadata.UpstreamPatches)
}

func TestGetPackageNameFromBranch(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "gnutls", repos.ExtractPackageName("bp-package-gnutls"))
	assert.Equal(t, "gnutls", repos.ExtractPackageName("package-gnutls"))
	assert.Equal(t, "gnutls", repos.ExtractPackageName("package-gnutls  "))
}
