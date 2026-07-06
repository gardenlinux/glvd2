package repos_test

import (
	"testing"

	"github.com/gardenlinux/glvd2/internal/gardenlinux/repos"
	"github.com/stretchr/testify/assert"
)

func TestIsBranchRelevant(t *testing.T) {
	t.Parallel()

	assert.True(t, repos.IsRelevantBranch(repos.Branch{Name: "main"}))
	assert.True(t, repos.IsRelevantBranch(repos.Branch{Name: "master"}))
	assert.True(t, repos.IsRelevantBranch(repos.Branch{Name: "rel-1592"}))
	assert.True(t, repos.IsRelevantBranch(repos.Branch{Name: "rel-1877"}))
	assert.True(t, repos.IsRelevantBranch(repos.Branch{Name: "rel-2150"}))

	assert.False(t, repos.IsRelevantBranch(repos.Branch{Name: "update/CVE"}))                  // bp-package-glib2.0
	assert.False(t, repos.IsRelevantBranch(repos.Branch{Name: "rel-1877-update"}))             // bp-package-sqlite3
	assert.False(t, repos.IsRelevantBranch(repos.Branch{Name: "rel-1443-refresh-for-6.6.76"})) // package-linux
	assert.False(t, repos.IsRelevantBranch(repos.Branch{Name: "fipsrel1877"}))                 // package-linux
}
