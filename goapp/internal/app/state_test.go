package app

import (
	"os"
	"path/filepath"
	"testing"

	ggm "puncture-go/internal/crypto"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	dir := t.TempDir()
	state, err := NewAppState(dir)
	if err != nil {
		t.Fatal(err)
	}
	plainPath := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(plainPath, []byte("alpha"), 0o644); err != nil {
		t.Fatal(err)
	}

	saved, errs, err := state.Encrypt([]string{"a.txt"}, 42, 555, "test")
	if err != nil {
		t.Fatalf("encrypt failed: %v (%v)", err, errs)
	}
	if len(saved) != 1 {
		t.Fatalf("expected 1 saved record")
	}

	restored, errs, err := state.Decrypt([]int{saved[0].RecordID})
	if err != nil {
		t.Fatalf("decrypt failed: %v (%v)", err, errs)
	}
	if len(restored) != 1 {
		t.Fatalf("expected one restored mapping")
	}
	rel := restored[0]["decrypted_relpath"].(string)
	content, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "alpha" {
		t.Fatalf("unexpected decrypted content: %q", string(content))
	}
}

func TestDecryptFailsAfterPuncture(t *testing.T) {
	dir := t.TempDir()
	state, err := NewAppState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("beta"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved, _, err := state.Encrypt([]string{"b.txt"}, 17, 700, "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Puncture(17, 700); err != nil {
		t.Fatal(err)
	}
	_, _, err = state.Decrypt([]int{saved[0].RecordID})
	if err == nil {
		t.Fatalf("expected decrypt to fail after puncture")
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	state1, err := NewAppState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.txt"), []byte("charlie"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := state1.Derive(42, 111, "persist me"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := state1.Encrypt([]string{"c.txt"}, 42, 111, "persist mapping"); err != nil {
		t.Fatal(err)
	}
	if err := state1.Puncture(42, 111); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(state1.StateFile); statErr != nil {
		t.Fatalf("expected persisted state file %q to exist: %v", state1.StateFile, statErr)
	}

	state2, err := NewAppState(dir)
	if err != nil {
		t.Fatal(err)
	}
	path, err := ggm.TagToBinaryPath(42, 111)
	if err != nil {
		t.Fatal(err)
	}
	_, ok, err := state2.Manager.GetKeyForTag(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatalf("expected punctured key to remain inaccessible after restart")
	}
	if len(state2.AssetRecords) != 1 {
		t.Fatalf("expected 1 persisted asset record, got %d", len(state2.AssetRecords))
	}
	entry := state2.KeyJournal[path]
	if entry == nil || !entry.EverPunctured {
		t.Fatalf("expected persisted key journal puncture entry")
	}
}

func TestDefaultStateFilePath(t *testing.T) {
	tmp := t.TempDir()
	assets := filepath.Join(tmp, "assets")
	state, err := NewAppState(assets)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(tmp, "state.json")
	if state.StateFile != want {
		t.Fatalf("expected state file %q, got %q", want, state.StateFile)
	}
}
