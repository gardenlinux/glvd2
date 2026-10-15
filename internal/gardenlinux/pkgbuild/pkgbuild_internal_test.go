package pkgbuild

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAnalyzeRecipe(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		want    BuildSignals
	}{
		{
			name: "commented apt_src still detects apply_patches",
			content: "# apt_src libgcrypt20\n" +
				"apply_patches\n" +
				`#version_suffix="gl3"`,
			want: BuildSignals{BuiltByGL: true, HasPatches: true},
		},
		{
			name: "salsa src with apply and upstream patches",
			content: "git_src -b debian/openssl-3.5.5-1 https://salsa.debian.org/debian/openssl.git\n" +
				"import_upstream_patches\n" +
				"apply_patches patches-debian\n" +
				`version_suffix="gl21"`,
			want: BuildSignals{BuiltByGL: true, SalsaSrc: true, HasPatches: true},
		},
		{
			name: "salsa src with upstream patches, package name in salsa url",
			content: "git_src_commit \"39488fe\" \"https://salsa.debian.org/selinux-team/refpolicy.git\"\n" +
				"import_upstream_patches",
			want: BuildSignals{BuiltByGL: true, SalsaSrc: true, HasPatches: true},
		},
		{
			name: "github upstream clone with apply_patches, version unknown",
			content: "git clone -b \"$UPSTREAM_VERSION\" --depth=1 https://github.com/canonical/checkbox.git \"$upstream\"\n" +
				"import_src \"$upstream/providers/gpgpu\"\n" +
				"apply_patches",
			want: BuildSignals{BuiltByGL: true, UpstreamSrc: true, HasPatches: true},
		},
		{
			name: "github upstream clone with a known version",
			content: "version_orig=7.2.0\n" +
				"git clone --depth=1 https://github.com/canonical/checkbox.git \"$upstream\"\n" +
				"import_src \"$upstream\"",
			want: BuildSignals{BuiltByGL: true, UpstreamSrc: true, UpstreamVersion: "7.2.0"},
		},
		{
			name: "upstream tarball plus salsa debian dir and patches",
			content: "curl -sSLf https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-3.8.12.tar.xz\n" +
				"git clone --depth 1 --branch 3.8.12-3 https://salsa.debian.org/gnutls-team/gnutls.git \"$salsadir\"\n" +
				"apply_patches",
			want: BuildSignals{BuiltByGL: true, UpstreamSrc: true, SalsaSrc: true, HasPatches: true},
		},
		{
			name: "upstream only, synthesized debian dir",
			content: "git clone --depth 1 https://github.com/GoogleCloudPlatform/guest-agent.git \"$workdir\"\n" +
				"import_src \"$workdir\"",
			want: BuildSignals{BuiltByGL: true, UpstreamSrc: true},
		},
		{
			name: "apt_src substring is not mistaken for the command",
			content: "my_apt_src thing\n" +
				"git_src -b debian/foo https://salsa.debian.org/debian/foo.git\n" +
				"apply_patches",
			want: BuildSignals{BuiltByGL: true, SalsaSrc: true, HasPatches: true},
		},
		{
			name: "debian mirror tarball is not upstream",
			content: "apt_src openssl\n" +
				"curl -sSLf https://deb.debian.org/debian/pool/main/o/openssl/openssl_3.5.5.orig.tar.gz\n",
			want: BuildSignals{BuiltByGL: true, AptSrc: true},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := analyzeRecipe(prepareScriptContent(tc.content))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		signals BuildSignals
		want    Provenance
	}{
		{"not built by gl", BuildSignals{}, ProvenanceTakenFromTesting},
		{"apt only", BuildSignals{BuiltByGL: true, AptSrc: true}, ProvenanceTakenFromTesting},
		{"salsa only", BuildSignals{BuiltByGL: true, SalsaSrc: true}, ProvenanceTakenFromTesting},
		{
			"apt plus patches",
			BuildSignals{BuiltByGL: true, AptSrc: true, HasPatches: true},
			ProvenancePatchedFromDebian,
		},
		{
			"salsa plus patches",
			BuildSignals{BuiltByGL: true, SalsaSrc: true, HasPatches: true},
			ProvenancePatchedFromDebian,
		},
		{
			"debian source wins over upstream tarball",
			BuildSignals{
				BuiltByGL:       true,
				SalsaSrc:        true,
				UpstreamSrc:     true,
				HasPatches:      true,
				UpstreamVersion: "3.8.12",
			},
			ProvenancePatchedFromDebian,
		},
		{
			"upstream with known version",
			BuildSignals{BuiltByGL: true, UpstreamSrc: true, UpstreamVersion: "7.2.0"},
			ProvenanceBuiltFromUpstream,
		},
		{
			"upstream without known version escalates",
			BuildSignals{BuiltByGL: true, UpstreamSrc: true},
			ProvenanceUnknown,
		},
		{"recipe with no recognizable signal", BuildSignals{BuiltByGL: true}, ProvenanceUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, classify(tc.signals))
		})
	}
}

func TestExtractUpstreamVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		want    string
	}{
		{"version_orig", "version_orig=20260522.00\n", "20260522.00"},
		{"UPSTREAM_VERSION strips v", "UPSTREAM_VERSION=\"v7.2.0\"\n", "7.2.0"},
		{"UPSTREAM_VERSION wins over version_orig", "version_orig=1.0\nUPSTREAM_VERSION=2.0\n", "2.0"},
		{"bare version is ignored", "version=7.2.0\n", ""},
		{"variable reference is ambiguous", "version_orig=\"2:${upstream}\"\n", ""},
		{"absent", "git clone x\n", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, extractUpstreamVersion(tc.content))
		})
	}
}

func TestVersionToTagAndStoreVersion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		version          string
		wantTag          string
		wantStoreVersion string
	}{
		{"non-backport identical", "2.3.5-0gl1", "2.3.5-0gl1", "2.3.5-0gl1"},
		{"backport tilde to plus", "2.3.5-0gl1~bp2150", "2.3.5-0gl1+bp2150", "2.3.5-0gl1~bp2150"},
		{"binNMU stripped for tag and key", "2.31-13+b1", "2.31-13", "2.31-13"},
		{"debian backport binNMU", "1.22.0-2~bpo12+1+b1", "1.22.0-2+bpo12+1", "1.22.0-2~bpo12+1"},
		{"update suffix kept", "1.2.3-1u1", "1.2.3-1u1", "1.2.3-1u1"},
		{"epoch stripped for tag, kept in key", "1:2.3-4gl1", "2.3-4gl1", "1:2.3-4gl1"},
		{"all tildes translated", "2.3~rc1-1gl1", "2.3+rc1-1gl1", "2.3~rc1-1gl1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.wantTag, versionToTag(tc.version))
			assert.Equal(t, tc.wantStoreVersion, storeVersion(tc.version))
		})
	}
}

func TestBackportSuffix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		version string
		want    bool
	}{
		{"gl backport", "3.8.12-3gl1~bp1877", true},
		{"gl backport zero rebuild", "8.21.0-2gl0~bp2150", true},
		{"non-backport gl rebuild", "3.8.12-3gl1", false},
		{"debian backport is not a gl backport", "1.22.0-2~bpo12+1", false},
		{"plain debian version", "2.31-13", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, backportSuffix.MatchString(tc.version))
		})
	}
}

func TestRepoCandidates(t *testing.T) {
	t.Parallel()

	assert.Equal(t, []string{"package-gnutls"}, repoCandidates("gnutls", "3.8.12-3gl1"))
	assert.Equal(
		t,
		[]string{"package-gnutls", "bp-package-gnutls"},
		repoCandidates("gnutls", "3.8.12-3gl1~bp1877"),
	)
}

func TestAppliedPatchDirs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		content string
		want    []string
	}{
		{"default debian dir", "apply_patches\n", []string{"patches"}},
		{"explicit debian dir", "apply_patches patches-debian\n", []string{"patches-debian"}},
		{"upstream default dir", "import_upstream_patches\n", []string{"upstream_patches"}},
		{
			"both with explicit dirs",
			"import_upstream_patches up\napply_patches patches-debian\n",
			[]string{"up", "patches-debian"},
		},
		{"explicit arg taken verbatim", "apply_patches --foo\n", []string{"--foo"}},
		{"keyword as argument is ignored", "echo apply_patches done\n", nil},
		{"keyword as substring is ignored", "my_apply_patches\n", nil},
		{"none", "git clone x\n", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, appliedPatchDirs(tc.content))
		})
	}
}

func TestSafePatchDir(t *testing.T) {
	t.Parallel()

	cases := []struct {
		dir  string
		want bool
	}{
		{"patches", true},
		{"patches-debian", true},
		{"debian/patches", true},
		{"upstream_patches", true},
		{"", false},
		{"/etc/passwd", false},
		{"..", false},
		{"../../etc", false},
		{"patches/..", false},
		{".", false},
		{"foo?ref=main", false},
		{"foo#frag", false},
		{"foo bar", false},
		{"foo%2e", false},
	}

	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, safePatchDir(tc.dir))
		})
	}
}

func TestCvesFromSeries(t *testing.T) {
	t.Parallel()

	series := "# patches\n" +
		"CVE-2024-1234.patch\n" +
		"0001-unrelated-fix.patch\n" +
		"cve-2023-9999.patch -p1\n" +
		"\n" +
		"#CVE-2020-0001.patch\n" +
		"CVE-2024-1234.patch\n" // duplicate

	got := cvesFromSeries(series)

	assert.Equal(t, []FixedCVE{
		{ID: "CVE-2024-1234", Kind: EvidenceKindPatchFilename},
		{ID: "CVE-2023-9999", Kind: EvidenceKindPatchFilename},
	}, got)
}

func TestCvesFromSeries_NoCVE(t *testing.T) {
	t.Parallel()

	assert.Empty(t, cvesFromSeries("0001-fix.patch\n0002-other.patch\n"))
}
