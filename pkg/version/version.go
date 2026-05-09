// Package version holds build-time version information.
// These variables are set at build time using ldflags:
//
//	go build -ldflags "-X github.com/gabbykarry/namd/pkg/version.Version=1.0.0" ./cmd/namd
//
// During development they default to "dev".
package version

import "fmt"

var (
	// Version is the semver release string e.g. "1.0.0"
	Version = "dev"

	// Commit is the git commit hash at build time e.g. "abc1234"
	Commit = "none"

	// Date is the build date e.g. "2026-05-10"
	Date = "unknown"
)

// String returns a formatted version string for display.
func String() string {
	return fmt.Sprintf("namd %s (commit %s, built %s)", Version, Commit, Date)
}
