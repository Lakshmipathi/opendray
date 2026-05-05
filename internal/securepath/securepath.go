// Package securepath validates filesystem paths are confined to a root,
// catching directory-traversal injections that filepath.Join alone won't
// reject. Use Join when constructing paths from any input that may
// contain user-supplied components (session IDs, plugin names, account
// IDs, file names from API requests, etc).
//
// The check is purely lexical — it does not call EvalSymlinks. Callers
// that need TOCTOU-safe symlink resolution should additionally re-check
// the resolved path after open. plugin/bridge/api_fs.go has the
// canonical two-step pattern (authorizePath + authorizeSymlinkResolved).
package securepath

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// ErrEscapesRoot is returned when the joined path resolves outside root.
// Callers can errors.Is this to distinguish escape attempts from other
// failures.
var ErrEscapesRoot = errors.New("path escapes root")

// Join cleans the join of root and parts and verifies the result is
// still inside root. Returns ErrEscapesRoot if the resulting path would
// escape root (e.g. via "..") and a wrapped error if root is not absolute.
//
// Behavioural notes:
//
//   - root must be absolute. Relative roots are rejected up front so
//     callers can't accidentally validate against a working-directory-
//     relative tree.
//   - Trailing separators on root are normalised by filepath.Clean.
//   - Empty parts are valid and return root unchanged.
//   - parts may contain leading separators; filepath.Join will not treat
//     them as absolute (only the first arg of Join is allowed to root
//     the result), so "/etc/passwd" passed as a part still mounts under
//     root. The Rel check then validates the joined result.
func Join(root string, parts ...string) (string, error) {
	if !filepath.IsAbs(root) {
		return "", fmt.Errorf("securepath: root must be absolute, got %q", root)
	}
	cleanRoot := filepath.Clean(root)
	cleanJoined := filepath.Clean(filepath.Join(append([]string{cleanRoot}, parts...)...))

	rel, err := filepath.Rel(cleanRoot, cleanJoined)
	if err != nil {
		return "", fmt.Errorf("securepath: rel %q from %q: %w", cleanJoined, cleanRoot, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("securepath: %q under %q: %w", cleanJoined, cleanRoot, ErrEscapesRoot)
	}
	return cleanJoined, nil
}
