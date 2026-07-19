package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHash_KnownVector(t *testing.T) {
	// echo -n "hello world" | sha256sum
	got := Hash([]byte("hello world"))
	want := "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
	if got != want {
		t.Errorf("Hash(%q) = %q, want %q", "hello world", got, want)
	}
}

func TestHash_Deterministic(t *testing.T) {
	data := []byte(`{"schema_version":1}`)
	first := Hash(data)
	second := Hash(data)
	if first != second {
		t.Errorf("Hash produced different output for identical input: %q vs %q", first, second)
	}
}

func TestWriteReadSidecar_RoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1}`), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	hash := Hash([]byte(`{"schema_version":1}`))

	if err := WriteSidecar(path, hash); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}
	got, err := ReadSidecar(path)
	if err != nil {
		t.Fatalf("ReadSidecar: %v", err)
	}
	if got != hash {
		t.Errorf("ReadSidecar = %q, want %q", got, hash)
	}
}

// TestWriteSidecar_UsesBaseNameOnly locks in that the sidecar names just
// the file's basename ("evidence.json"), not its full path — a sidecar
// checked with `sha256sum -c` from within outDir must reference the file
// as it actually appears in that directory, not wherever attestward itself
// happened to run from.
func TestWriteSidecar_UsesBaseNameOnly(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	if err := os.Mkdir(subdir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", subdir, err)
	}
	path := filepath.Join(subdir, "evidence.json")
	if err := WriteSidecar(path, Hash([]byte("x"))); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}
	data, err := os.ReadFile(SidecarPath(path))
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	want := Hash([]byte("x")) + "  evidence.json\n"
	if string(data) != want {
		t.Errorf("sidecar content = %q, want %q", data, want)
	}
}

// TestSidecarFormat_MatchesGNUCoreutilsConvention locks in the exact
// on-disk format ("<hash>  <filename>\n", two spaces) so a plain
// `sha256sum -c evidence.json.sha256` (no attestward involved at all) can
// verify a pack — issue #27's own acceptance criterion.
func TestSidecarFormat_MatchesGNUCoreutilsConvention(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	hash := Hash([]byte("x"))
	if err := WriteSidecar(path, hash); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}
	data, err := os.ReadFile(SidecarPath(path))
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	want := hash + "  evidence.json\n"
	if string(data) != want {
		t.Errorf("sidecar = %q, want %q (GNU coreutils sha256sum text-mode format)", data, want)
	}
}

func TestReadSidecar_BinaryModeSeparatorTolerated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	hash := Hash([]byte("x"))
	// GNU coreutils' binary-mode output: "<hash> *<filename>\n".
	if err := os.WriteFile(SidecarPath(path), []byte(hash+" *evidence.json\n"), 0o644); err != nil {
		t.Fatalf("write binary-mode sidecar: %v", err)
	}
	got, err := ReadSidecar(path)
	if err != nil {
		t.Fatalf("ReadSidecar: %v", err)
	}
	if got != hash {
		t.Errorf("ReadSidecar = %q, want %q", got, hash)
	}
}

func TestReadSidecar_MalformedIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(SidecarPath(path), []byte("not-a-hash evidence.json\n"), 0o644); err != nil {
		t.Fatalf("write malformed sidecar: %v", err)
	}
	if _, err := ReadSidecar(path); err == nil {
		t.Error("ReadSidecar on a malformed sidecar returned no error, want one")
	}
}

func TestReadSidecar_MissingIsError(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadSidecar(filepath.Join(dir, "evidence.json")); err == nil {
		t.Error("ReadSidecar with no sidecar file returned no error, want one")
	}
}

func TestVerifyFile_MatchingHashPasses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	content := []byte(`{"schema_version":1}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := WriteSidecar(path, Hash(content)); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}

	ok, got, want, err := VerifyFile(path)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if !ok {
		t.Errorf("VerifyFile ok = false, want true (got %q, want %q)", got, want)
	}
}

// TestVerifyFile_TamperedByteFails is issue #27's own named acceptance
// case: "single-byte tamper fails" verification.
func TestVerifyFile_TamperedByteFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "evidence.json")
	content := []byte(`{"schema_version":1}`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := WriteSidecar(path, Hash(content)); err != nil {
		t.Fatalf("WriteSidecar: %v", err)
	}

	tampered := append([]byte{}, content...)
	tampered[0] = 'X'
	if err := os.WriteFile(path, tampered, 0o644); err != nil {
		t.Fatalf("tamper fixture: %v", err)
	}

	ok, got, want, err := VerifyFile(path)
	if err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
	if ok {
		t.Error("VerifyFile ok = true on a tampered file, want false")
	}
	if got == want {
		t.Error("VerifyFile's got/want hashes are equal despite the tamper — test itself is broken")
	}
}

func TestVerifyFile_MissingEvidenceFileIsError(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := VerifyFile(filepath.Join(dir, "evidence.json")); err == nil {
		t.Error("VerifyFile with no evidence.json returned no error, want one")
	}
}
