package crypto

import "testing"

func mustSeed() []byte {
	seed := make([]byte, KeySize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return seed
}

func TestDeriveAndPuncture(t *testing.T) {
	mgr, err := NewManager(mustSeed())
	if err != nil {
		t.Fatal(err)
	}
	path, err := TagToBinaryPath(42, 123456)
	if err != nil {
		t.Fatal(err)
	}
	before, ok, err := mgr.GetKeyForTag(path)
	if err != nil || !ok || len(before) != 32 {
		t.Fatalf("derive before puncture failed: ok=%v err=%v", ok, err)
	}
	applied, err := mgr.Puncture(path)
	if err != nil || !applied {
		t.Fatalf("puncture failed: applied=%v err=%v", applied, err)
	}
	after, ok, err := mgr.GetKeyForTag(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok || after != nil {
		t.Fatalf("expected punctured key to be inaccessible")
	}
}

func TestProviderPrefixPuncture(t *testing.T) {
	mgr, err := NewManager(mustSeed())
	if err != nil {
		t.Fatal(err)
	}
	p42a, _ := TagToBinaryPath(42, 100)
	p42b, _ := TagToBinaryPath(42, 101)
	p41, _ := TagToBinaryPath(41, 100)
	k41Before, ok, _ := mgr.GetKeyForTag(p41)
	if !ok {
		t.Fatalf("control key should be derivable")
	}
	applied, err := mgr.PunctureProvider(42)
	if err != nil || !applied {
		t.Fatalf("provider puncture failed: %v", err)
	}
	if _, ok, _ := mgr.GetKeyForTag(p42a); ok {
		t.Fatalf("p42 key should be blocked")
	}
	if _, ok, _ := mgr.GetKeyForTag(p42b); ok {
		t.Fatalf("p42 key should be blocked")
	}
	k41After, ok, _ := mgr.GetKeyForTag(p41)
	if !ok {
		t.Fatalf("p41 key should remain derivable")
	}
	if string(k41Before) != string(k41After) {
		t.Fatalf("p41 key changed unexpectedly")
	}
}
