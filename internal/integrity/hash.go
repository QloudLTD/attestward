package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Hash returns the lowercase hex-encoded SHA-256 digest of data. It's the
// single source of truth for "the hash of an evidence pack" — every other
// function in this package, and every caller printing/embedding a pack's
// hash, must compute it exactly this way so the three places issue #27
// requires the hash to appear (stdout, report.md/html's Integrity.SHA256,
// the .sha256 sidecar) can never silently disagree.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SidecarPath is the conventional sidecar path for path — evidence.json ->
// evidence.json.sha256.
func SidecarPath(path string) string {
	return path + ".sha256"
}

// WriteSidecar writes hash for the file named path (basename only, not the
// full path — a sidecar checked with `sha256sum -c` must name its target
// relative to the sidecar's own directory) to SidecarPath(path), in
// standard sha256sum/shasum text-mode format: "<hash>  <filename>\n" (two
// spaces — one literal, one the text-mode indicator GNU coreutils and BSD
// shasum both expect) — so `sha256sum -c evidence.json.sha256` and
// `shasum -a 256 -c evidence.json.sha256`, run from the same directory,
// both verify it without attestor's own involvement. Matches this
// project's already-established checksums.txt convention (see
// .goreleaser.yaml / SECURITY.md) rather than inventing a new format.
func WriteSidecar(path, hash string) error {
	line := fmt.Sprintf("%s  %s\n", hash, filepath.Base(path))
	if err := os.WriteFile(SidecarPath(path), []byte(line), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", SidecarPath(path), err)
	}
	return nil
}

// ReadSidecar parses the hash out of SidecarPath(path) — the inverse of
// WriteSidecar, tolerant of either the GNU text-mode ("  ") or binary-mode
// (" *") separator so a sidecar produced by a different sha256sum-family
// tool still verifies.
func ReadSidecar(path string) (string, error) {
	sidecarPath := SidecarPath(path)
	data, err := os.ReadFile(sidecarPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", sidecarPath, err)
	}
	line := strings.TrimRight(string(data), "\n")
	hash, _, ok := strings.Cut(line, " ")
	if !ok || len(hash) != 64 {
		return "", fmt.Errorf("%s is not in sha256sum format (expected \"<64-char hash>  <filename>\", got %q)", sidecarPath, line)
	}
	return hash, nil
}

// VerifyFile recomputes the SHA-256 of path's current contents and
// compares it against SidecarPath(path). ok is true only when the sidecar
// exists, is well-formed, and matches — a missing or malformed sidecar is
// a real error (something an operator needs to notice), not silently
// treated as "unverifiable, assume fine".
func VerifyFile(path string) (ok bool, gotHash, wantHash string, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, "", "", fmt.Errorf("read %s: %w", path, err)
	}
	gotHash = Hash(data)
	wantHash, err = ReadSidecar(path)
	if err != nil {
		return false, gotHash, "", err
	}
	return strings.EqualFold(gotHash, wantHash), gotHash, wantHash, nil
}
