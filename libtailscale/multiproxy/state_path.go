package multiproxy

import (
	"fmt"
	"os"
	"path/filepath"
)

// StateDirForIdentifier returns the deterministic per-profile tsnet state path.
// The path component is derived only from the immutable profile identifier hash.
func StateDirForIdentifier(dataDir, identifier string) string {
	return filepath.Join(dataDir, fmt.Sprintf("state-%s", getStableHash(identifier)))
}

// ForgetPersistedState removes only the persisted state directory belonging to
// identifier. It is used when Android forgets a profile while no Engine is live.
func ForgetPersistedState(dataDir, identifier string) error {
	return os.RemoveAll(StateDirForIdentifier(dataDir, identifier))
}
