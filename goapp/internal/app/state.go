package app

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	ggm "puncture-go/internal/crypto"
)

const (
	encMagic     = "PKE1"
	encNonceSize = 16
	encTagSize   = 32
	treeDepth    = 7
)

type Provider struct {
	ProviderID  int    `json:"provider_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at"`
}

type DeletedProvider struct {
	ProviderID int    `json:"provider_id"`
	Name       string `json:"name"`
	Prefix     string `json:"prefix"`
	DeletedAt  string `json:"deleted_at"`
	Applied    bool   `json:"applied"`
}

type KeyJournalEntry struct {
	ProviderID      int    `json:"provider_id"`
	FileTimeID      int    `json:"file_time_id"`
	Path            string `json:"path"`
	PathProvider    string `json:"path_provider"`
	PathResource    string `json:"path_resource"`
	Description     string `json:"description"`
	EverDerived     bool   `json:"ever_derived"`
	EverPunctured   bool   `json:"ever_punctured"`
	DeriveCount     int    `json:"derive_count"`
	PunctureCount   int    `json:"puncture_count"`
	LastDerivedAt   string `json:"last_derived_at,omitempty"`
	LastPuncturedAt string `json:"last_punctured_at,omitempty"`
}

type AssetRecord struct {
	RecordID          int    `json:"record_id"`
	PlaintextRelpath  string `json:"plaintext_relpath"`
	CiphertextRelpath string `json:"ciphertext_relpath"`
	ProviderID        int    `json:"provider_id"`
	FileTimeID        int    `json:"file_time_id"`
	Path              string `json:"path"`
	Purpose           string `json:"purpose"`
	CreatedAt         string `json:"created_at"`
	PlaintextSize     int    `json:"plaintext_size"`
	CiphertextSize    int    `json:"ciphertext_size"`
	DecryptCount      int    `json:"decrypt_count"`
	LastDecryptedAt   string `json:"last_decrypted_at,omitempty"`
	LastDecryptedRel  string `json:"last_decrypted_relpath,omitempty"`
}

type LastAction struct {
	Tone         string `json:"tone"`
	Title        string `json:"title"`
	Body         string `json:"body"`
	ProviderID   *int   `json:"provider_id"`
	FileTimeID   *int   `json:"file_time_id"`
	Path         string `json:"path,omitempty"`
	PathProvider string `json:"path_provider,omitempty"`
	PathResource string `json:"path_resource,omitempty"`
	KeyHex       string `json:"key_hex,omitempty"`
	KeyDesc      string `json:"key_description,omitempty"`
}

type HistoryItem struct {
	Time       string `json:"time"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	Summary    string `json:"summary"`
	ProviderID *int   `json:"provider_id"`
	FileTimeID *int   `json:"file_time_id"`
	Path       string `json:"path,omitempty"`
}

type LastPunctureDiff struct {
	Time       string   `json:"time"`
	Target     string   `json:"target"`
	TargetKind string   `json:"target_kind"`
	Removed    []string `json:"removed"`
	Added      []string `json:"added"`
}

type LastInputs struct {
	ProviderID int    `json:"provider_id"`
	FileTimeID int    `json:"file_time_id"`
	Purpose    string `json:"purpose"`
}

type Notice struct {
	Tone    string `json:"tone"`
	Message string `json:"message"`
}

type TreeViz struct {
	Depth                int               `json:"depth"`
	CurrentFrontierCount int               `json:"current_frontier_count"`
	BlockedCount         int               `json:"blocked_count"`
	RemovedCount         int               `json:"removed_count"`
	LastPuncture         *LastPunctureDiff `json:"last_puncture,omitempty"`
	SVG                  string            `json:"svg"`
}

type AppState struct {
	mu sync.RWMutex

	Manager *ggm.Manager

	Providers        map[int]Provider
	DeletedProviders []DeletedProvider
	KeyJournal       map[string]*KeyJournalEntry
	AssetRecords     []*AssetRecord
	AssetRoot        string
	StateFile        string

	LastInputs       LastInputs
	LastAction       LastAction
	History          []HistoryItem
	LastPunctureDiff *LastPunctureDiff

	ProvidersNotice *Notice
	AssetNotice     *Notice
}

type persistedState struct {
	Version          int                         `json:"version"`
	Manager          ggm.ExportState             `json:"manager"`
	Providers        map[int]Provider            `json:"providers"`
	DeletedProviders []DeletedProvider           `json:"deleted_providers"`
	KeyJournal       map[string]*KeyJournalEntry `json:"key_journal"`
	AssetRecords     []*AssetRecord              `json:"asset_records"`
	History          []HistoryItem               `json:"history"`
	LastAction       LastAction                  `json:"last_action"`
	LastInputs       LastInputs                  `json:"last_inputs"`
	LastPunctureDiff *LastPunctureDiff           `json:"last_puncture_diff"`
}

func nowLabel() string {
	return time.Now().UTC().Format("15:04:05 UTC")
}

func defaultProviders() map[int]Provider {
	now := nowLabel()
	return map[int]Provider{
		42: {ProviderID: 42, Name: "Provider 42 (Demo)", Description: "Default provider used in Scenario A walkthrough.", CreatedAt: now},
		17: {ProviderID: 17, Name: "Northwind Cloud", Description: "Example provider entry.", CreatedAt: now},
		88: {ProviderID: 88, Name: "Blue Harbor Storage", Description: "Example provider entry.", CreatedAt: now},
	}
}

func defaultStateFilePath(assetRoot string) string {
	if v := strings.TrimSpace(os.Getenv("PUNCTURE_STATE_FILE")); v != "" {
		if abs, err := filepath.Abs(v); err == nil {
			return abs
		}
		return v
	}
	if filepath.Base(assetRoot) == "assets" {
		return filepath.Join(filepath.Dir(assetRoot), "state.json")
	}
	return filepath.Join(assetRoot, ".puncture-state.json")
}

func sanitizeAssetRecords(records []*AssetRecord) []*AssetRecord {
	if records == nil {
		return []*AssetRecord{}
	}
	out := make([]*AssetRecord, 0, len(records))
	nextID := 1
	used := map[int]struct{}{}
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if rec.RecordID <= 0 {
			rec.RecordID = nextID
		}
		for {
			if _, exists := used[rec.RecordID]; !exists {
				break
			}
			rec.RecordID++
		}
		used[rec.RecordID] = struct{}{}
		if rec.RecordID >= nextID {
			nextID = rec.RecordID + 1
		}
		out = append(out, rec)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RecordID < out[j].RecordID })
	return out
}

func NewAppState(assetRoot string) (*AppState, error) {
	if assetRoot == "" {
		assetRoot = filepath.Join(".", "assets")
	}
	absRoot, err := filepath.Abs(assetRoot)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absRoot, 0o755); err != nil {
		return nil, err
	}
	stateFile := defaultStateFilePath(absRoot)
	seed, err := ggm.GenerateMasterSeed()
	if err != nil {
		return nil, err
	}
	mgr, err := ggm.NewManager(seed)
	if err != nil {
		return nil, err
	}
	s := &AppState{
		Manager:          mgr,
		Providers:        defaultProviders(),
		DeletedProviders: []DeletedProvider{},
		KeyJournal:       map[string]*KeyJournalEntry{},
		AssetRecords:     []*AssetRecord{},
		AssetRoot:        absRoot,
		StateFile:        stateFile,
		LastInputs:       LastInputs{ProviderID: 42, FileTimeID: 123456, Purpose: "Demo key for provider onboarding"},
		LastAction:       LastAction{Tone: "info", Title: "Welcome", Body: "Derive a key and puncture it to observe forward secrecy."},
		History:          []HistoryItem{},
		LastPunctureDiff: nil,
		ProvidersNotice:  nil,
		AssetNotice:      nil,
	}
	if err := s.loadPersistedStateLocked(); err != nil {
		if _, statErr := os.Stat(s.StateFile); statErr == nil {
			backup := s.StateFile + ".corrupt." + time.Now().UTC().Format("20060102T150405")
			_ = os.Rename(s.StateFile, backup)
			s.LastAction = LastAction{
				Tone:  "warn",
				Title: "State recovered",
				Body:  fmt.Sprintf("Persisted state was invalid and moved to %s; using fresh state.", filepath.Base(backup)),
			}
		}
	}
	s.persistLockedNoFail()
	return s, nil
}

func ptrInt(v int) *int { return &v }

func (s *AppState) setLastAction(a LastAction) {
	s.LastAction = a
}

func (s *AppState) recordHistory(action, status, summary string, providerID, fileTimeID *int, path string) {
	s.History = append([]HistoryItem{{
		Time:       nowLabel(),
		Action:     action,
		Status:     status,
		Summary:    summary,
		ProviderID: providerID,
		FileTimeID: fileTimeID,
		Path:       path,
	}}, s.History...)
	if len(s.History) > 40 {
		s.History = s.History[:40]
	}
}

func (s *AppState) persistedPayloadLocked() persistedState {
	return persistedState{
		Version:          1,
		Manager:          s.Manager.ExportState(),
		Providers:        s.Providers,
		DeletedProviders: s.DeletedProviders,
		KeyJournal:       s.KeyJournal,
		AssetRecords:     s.AssetRecords,
		History:          s.History,
		LastAction:       s.LastAction,
		LastInputs:       s.LastInputs,
		LastPunctureDiff: s.LastPunctureDiff,
	}
}

func (s *AppState) persistLocked() error {
	if strings.TrimSpace(s.StateFile) == "" {
		return nil
	}
	payload := s.persistedPayloadLocked()
	blob, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.StateFile), 0o755); err != nil {
		return err
	}
	tmp := s.StateFile + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.StateFile)
}

func (s *AppState) persistLockedNoFail() {
	if err := s.persistLocked(); err != nil {
		fmt.Fprintf(os.Stderr, "puncture-go: failed to persist state: %v\n", err)
	}
}

func (s *AppState) applyPersistedStateLocked(p persistedState) error {
	mgr, err := ggm.FromState(p.Manager)
	if err != nil {
		return err
	}
	s.Manager = mgr

	if p.Providers != nil {
		s.Providers = p.Providers
	} else {
		s.Providers = defaultProviders()
	}
	if p.DeletedProviders != nil {
		s.DeletedProviders = p.DeletedProviders
	} else {
		s.DeletedProviders = []DeletedProvider{}
	}
	if p.KeyJournal != nil {
		s.KeyJournal = p.KeyJournal
	} else {
		s.KeyJournal = map[string]*KeyJournalEntry{}
	}
	s.AssetRecords = sanitizeAssetRecords(p.AssetRecords)
	if p.History != nil {
		s.History = p.History
	} else {
		s.History = []HistoryItem{}
	}
	if len(s.History) > 40 {
		s.History = s.History[:40]
	}
	s.LastAction = p.LastAction
	if strings.TrimSpace(s.LastAction.Title) == "" {
		s.LastAction = LastAction{Tone: "info", Title: "Welcome", Body: "Derive a key and puncture it to observe forward secrecy."}
	}
	s.LastInputs = p.LastInputs
	if s.LastInputs.ProviderID == 0 && s.LastInputs.FileTimeID == 0 && strings.TrimSpace(s.LastInputs.Purpose) == "" {
		s.LastInputs = LastInputs{ProviderID: 42, FileTimeID: 123456, Purpose: "Demo key for provider onboarding"}
	}
	s.LastPunctureDiff = p.LastPunctureDiff
	s.ProvidersNotice = nil
	s.AssetNotice = nil
	return nil
}

func (s *AppState) loadPersistedStateLocked() error {
	if strings.TrimSpace(s.StateFile) == "" {
		return nil
	}
	blob, err := os.ReadFile(s.StateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var payload persistedState
	if err := json.Unmarshal(blob, &payload); err != nil {
		return err
	}
	if payload.Manager.ActiveNodes == nil && payload.Manager.PunctureLog == nil {
		return errors.New("persisted state missing manager payload")
	}
	return s.applyPersistedStateLocked(payload)
}

func splitPath(path string) (string, string) {
	if len(path) < 7 {
		return path, ""
	}
	return path[:7], path[7:]
}

func (s *AppState) ensureKeyEntry(providerID, fileTimeID int, path string) *KeyJournalEntry {
	entry, ok := s.KeyJournal[path]
	if ok {
		return entry
	}
	pp, pr := splitPath(path)
	entry = &KeyJournalEntry{
		ProviderID:   providerID,
		FileTimeID:   fileTimeID,
		Path:         path,
		PathProvider: pp,
		PathResource: pr,
	}
	s.KeyJournal[path] = entry
	return entry
}

func (s *AppState) touchKeyDerive(providerID, fileTimeID int, path, desc string) *KeyJournalEntry {
	entry := s.ensureKeyEntry(providerID, fileTimeID, path)
	if strings.TrimSpace(desc) != "" {
		entry.Description = strings.TrimSpace(desc)
	}
	entry.EverDerived = true
	entry.DeriveCount++
	entry.LastDerivedAt = nowLabel()
	return entry
}

func (s *AppState) touchKeyPuncture(providerID, fileTimeID int, path string, applied bool) *KeyJournalEntry {
	entry := s.ensureKeyEntry(providerID, fileTimeID, path)
	entry.EverPunctured = true
	if applied {
		entry.PunctureCount++
	}
	entry.LastPuncturedAt = nowLabel()
	return entry
}

func sortedPrefixes(prefixes []string) []string {
	out := append([]string(nil), prefixes...)
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) == len(out[j]) {
			return out[i] < out[j]
		}
		return len(out[i]) < len(out[j])
	})
	return out
}

func (s *AppState) setLastPunctureDiff(beforeFrontier, afterFrontier []string, target, kind string) {
	beforeSet := map[string]struct{}{}
	afterSet := map[string]struct{}{}
	for _, p := range beforeFrontier {
		beforeSet[p] = struct{}{}
	}
	for _, p := range afterFrontier {
		afterSet[p] = struct{}{}
	}
	removed := make([]string, 0)
	added := make([]string, 0)
	for _, p := range beforeFrontier {
		if _, ok := afterSet[p]; !ok {
			removed = append(removed, p)
		}
	}
	for _, p := range afterFrontier {
		if _, ok := beforeSet[p]; !ok {
			added = append(added, p)
		}
	}
	s.LastPunctureDiff = &LastPunctureDiff{
		Time:       nowLabel(),
		Target:     target,
		TargetKind: kind,
		Removed:    sortedPrefixes(removed),
		Added:      sortedPrefixes(added),
	}
}

func normalizeRelPath(rel string) (string, error) {
	rel = strings.TrimSpace(rel)
	if rel == "" {
		return "", errors.New("relative file path is required")
	}
	if filepath.IsAbs(rel) {
		return "", errors.New("absolute paths are not allowed")
	}
	n := filepath.Clean(rel)
	n = filepath.ToSlash(n)
	if n == "." || strings.HasPrefix(n, "../") || n == ".." {
		return "", errors.New("path traversal is not allowed")
	}
	return n, nil
}

func assetAbsPath(root, rel string) (string, error) {
	n, err := normalizeRelPath(rel)
	if err != nil {
		return "", err
	}
	abs := filepath.Clean(filepath.Join(root, filepath.FromSlash(n)))
	if abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator)) {
		return "", errors.New("file path escapes asset root")
	}
	return abs, nil
}

func nextRelPath(root, desired string) (string, error) {
	n, err := normalizeRelPath(desired)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(n)
	if dir == "." {
		dir = ""
	}
	base := filepath.Base(n)
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	for i := 1; ; i++ {
		cand := base
		if i > 1 {
			cand = fmt.Sprintf("%s.v%d%s", stem, i, ext)
		}
		rel := cand
		if dir != "" {
			rel = filepath.ToSlash(filepath.Join(dir, cand))
		}
		abs, err := assetAbsPath(root, rel)
		if err != nil {
			return "", err
		}
		if _, statErr := os.Stat(abs); errors.Is(statErr, os.ErrNotExist) {
			return rel, nil
		}
	}
}

func nextCiphertextRelPath(root, plaintextRel string, providerID, fileTimeID int) (string, error) {
	n, err := normalizeRelPath(plaintextRel)
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(n)
	if dir == "." {
		dir = ""
	}
	filename := filepath.Base(n)
	stem := fmt.Sprintf("%s.enc.p%d.k%d", filename, providerID, fileTimeID)
	for i := 1; ; i++ {
		suffix := ".pke"
		if i > 1 {
			suffix = fmt.Sprintf(".v%d.pke", i)
		}
		cand := stem + suffix
		rel := cand
		if dir != "" {
			rel = filepath.ToSlash(filepath.Join(dir, cand))
		}
		abs, err := assetAbsPath(root, rel)
		if err != nil {
			return "", err
		}
		if _, statErr := os.Stat(abs); errors.Is(statErr, os.ErrNotExist) {
			return rel, nil
		}
	}
}

func nextDecryptedRelPath(root, plaintextRel string, providerID, fileTimeID int) (string, error) {
	target := fmt.Sprintf("%s.dec.p%d.k%d", plaintextRel, providerID, fileTimeID)
	return nextRelPath(root, target)
}

func streamXOR(key, nonce, data []byte) []byte {
	out := make([]byte, len(data))
	off := 0
	counter := uint64(0)
	for off < len(data) {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("ENC"))
		mac.Write(nonce)
		ctr := []byte{
			byte(counter >> 56), byte(counter >> 48), byte(counter >> 40), byte(counter >> 32),
			byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter),
		}
		mac.Write(ctr)
		block := mac.Sum(nil)
		chunk := block
		if len(data)-off < len(block) {
			chunk = block[:len(data)-off]
		}
		for i := range chunk {
			out[off+i] = data[off+i] ^ chunk[i]
		}
		off += len(chunk)
		counter++
	}
	return out
}

func encryptBlob(key, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, encNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := streamXOR(key, nonce, plaintext)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("TAG"))
	mac.Write(nonce)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	blob := make([]byte, 0, len(encMagic)+len(nonce)+len(tag)+len(ciphertext))
	blob = append(blob, []byte(encMagic)...)
	blob = append(blob, nonce...)
	blob = append(blob, tag...)
	blob = append(blob, ciphertext...)
	return blob, nil
}

func decryptBlob(key, blob []byte) ([]byte, error) {
	min := len(encMagic) + encNonceSize + encTagSize
	if len(blob) < min {
		return nil, errors.New("ciphertext too short")
	}
	if string(blob[:len(encMagic)]) != encMagic {
		return nil, errors.New("ciphertext header mismatch")
	}
	nonceStart := len(encMagic)
	nonceEnd := nonceStart + encNonceSize
	tagEnd := nonceEnd + encTagSize
	nonce := blob[nonceStart:nonceEnd]
	tag := blob[nonceEnd:tagEnd]
	ciphertext := blob[tagEnd:]

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("TAG"))
	mac.Write(nonce)
	mac.Write(ciphertext)
	expected := mac.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return nil, errors.New("ciphertext authentication failed")
	}
	return streamXOR(key, nonce, ciphertext), nil
}

func (s *AppState) Derive(providerID, fileTimeID int, purpose string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	path, err := ggm.TagToBinaryPath(providerID, fileTimeID)
	if err != nil {
		return err
	}
	s.LastInputs = LastInputs{ProviderID: providerID, FileTimeID: fileTimeID, Purpose: purpose}
	key, ok, err := s.Manager.GetKeyForTag(path)
	if err != nil {
		return err
	}
	if !ok {
		s.setLastAction(LastAction{
			Tone:         "warn",
			Title:        "Derive blocked",
			Body:         "Key is inaccessible due to prior puncture.",
			ProviderID:   ptrInt(providerID),
			FileTimeID:   ptrInt(fileTimeID),
			Path:         path,
			PathProvider: path[:7],
			PathResource: path[7:],
		})
		s.recordHistory("derive", "void", fmt.Sprintf("Derive blocked for provider=%d,file=%d", providerID, fileTimeID), ptrInt(providerID), ptrInt(fileTimeID), path)
		return nil
	}
	entry := s.touchKeyDerive(providerID, fileTimeID, path, purpose)
	s.setLastAction(LastAction{
		Tone:         "success",
		Title:        "Derive succeeded",
		Body:         "Key derivation succeeded.",
		ProviderID:   ptrInt(providerID),
		FileTimeID:   ptrInt(fileTimeID),
		Path:         path,
		PathProvider: path[:7],
		PathResource: path[7:],
		KeyHex:       fmt.Sprintf("%x", key),
		KeyDesc:      entry.Description,
	})
	s.recordHistory("derive", "derived", fmt.Sprintf("Derived key for provider=%d,file=%d", providerID, fileTimeID), ptrInt(providerID), ptrInt(fileTimeID), path)
	return nil
}

func (s *AppState) Puncture(providerID, fileTimeID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	path, err := ggm.TagToBinaryPath(providerID, fileTimeID)
	if err != nil {
		return err
	}
	before := s.Manager.ActivePrefixes()
	applied, err := s.Manager.Puncture(path)
	if err != nil {
		return err
	}
	after := s.Manager.ActivePrefixes()
	s.setLastPunctureDiff(before, after, path, "tag")
	entry := s.touchKeyPuncture(providerID, fileTimeID, path, applied)
	s.LastInputs = LastInputs{ProviderID: providerID, FileTimeID: fileTimeID, Purpose: s.LastInputs.Purpose}
	if applied {
		s.setLastAction(LastAction{Tone: "success", Title: "Puncture succeeded", Body: "Target tag is now permanently inaccessible.", ProviderID: ptrInt(providerID), FileTimeID: ptrInt(fileTimeID), Path: path, PathProvider: path[:7], PathResource: path[7:], KeyDesc: entry.Description})
		s.recordHistory("puncture", "applied", fmt.Sprintf("Punctured provider=%d,file=%d", providerID, fileTimeID), ptrInt(providerID), ptrInt(fileTimeID), path)
	} else {
		s.setLastAction(LastAction{Tone: "warn", Title: "Puncture no-op", Body: "Target was already inaccessible.", ProviderID: ptrInt(providerID), FileTimeID: ptrInt(fileTimeID), Path: path, PathProvider: path[:7], PathResource: path[7:], KeyDesc: entry.Description})
		s.recordHistory("puncture", "noop", fmt.Sprintf("No-op puncture provider=%d,file=%d", providerID, fileTimeID), ptrInt(providerID), ptrInt(fileTimeID), path)
	}
	return nil
}

func (s *AppState) markProviderKeysPunctured(providerID int) int {
	n := 0
	stamp := nowLabel()
	for _, entry := range s.KeyJournal {
		if entry.ProviderID != providerID {
			continue
		}
		if !entry.EverPunctured {
			entry.PunctureCount++
		}
		entry.EverPunctured = true
		entry.LastPuncturedAt = stamp
		n++
	}
	return n
}

func (s *AppState) PunctureProvider(providerID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	prefix, err := ggm.ProviderIDToPrefix(providerID)
	if err != nil {
		return err
	}
	before := s.Manager.ActivePrefixes()
	applied, err := s.Manager.PunctureProvider(providerID)
	if err != nil {
		return err
	}
	after := s.Manager.ActivePrefixes()
	s.setLastPunctureDiff(before, after, prefix, "provider-prefix")
	touched := s.markProviderKeysPunctured(providerID)
	s.setLastAction(LastAction{Tone: "warn", Title: "Provider prefix punctured", Body: fmt.Sprintf("Provider %d punctured; keys in subtree blocked (known=%d).", providerID, touched), ProviderID: ptrInt(providerID)})
	status := "already-inaccessible"
	if applied {
		status = "punctured"
	}
	s.recordHistory("provider-puncture", status, fmt.Sprintf("Provider %d prefix punctured", providerID), ptrInt(providerID), nil, prefix)
	return nil
}

func (s *AppState) AddProvider(providerID int, name, description string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	if strings.TrimSpace(name) == "" {
		return errors.New("name is required")
	}
	if _, err := ggm.ProviderIDToPrefix(providerID); err != nil {
		return err
	}
	if _, exists := s.Providers[providerID]; exists {
		return fmt.Errorf("provider %d already exists", providerID)
	}
	s.Providers[providerID] = Provider{ProviderID: providerID, Name: strings.TrimSpace(name), Description: strings.TrimSpace(description), CreatedAt: nowLabel()}
	s.ProvidersNotice = &Notice{Tone: "success", Message: fmt.Sprintf("Added provider %d", providerID)}
	s.recordHistory("provider-add", "added", fmt.Sprintf("Added provider %d", providerID), ptrInt(providerID), nil, "")
	return nil
}

func (s *AppState) EditProvider(providerID int, name, description string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	p, ok := s.Providers[providerID]
	if !ok {
		return fmt.Errorf("provider %d does not exist", providerID)
	}
	if strings.TrimSpace(name) == "" {
		return errors.New("name is required")
	}
	p.Name = strings.TrimSpace(name)
	p.Description = strings.TrimSpace(description)
	s.Providers[providerID] = p
	s.ProvidersNotice = &Notice{Tone: "success", Message: fmt.Sprintf("Updated provider %d", providerID)}
	s.recordHistory("provider-edit", "updated", fmt.Sprintf("Updated provider %d", providerID), ptrInt(providerID), nil, "")
	return nil
}

func (s *AppState) DeleteProvider(providerID int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	p, ok := s.Providers[providerID]
	if !ok {
		return fmt.Errorf("provider %d does not exist", providerID)
	}
	prefix, _ := ggm.ProviderIDToPrefix(providerID)
	before := s.Manager.ActivePrefixes()
	applied, err := s.Manager.PuncturePrefix(prefix)
	if err != nil {
		return err
	}
	after := s.Manager.ActivePrefixes()
	s.setLastPunctureDiff(before, after, prefix, "provider-prefix")
	known := s.markProviderKeysPunctured(providerID)
	delete(s.Providers, providerID)
	s.DeletedProviders = append([]DeletedProvider{{ProviderID: providerID, Name: p.Name, Prefix: prefix, DeletedAt: nowLabel(), Applied: applied}}, s.DeletedProviders...)
	if len(s.DeletedProviders) > 32 {
		s.DeletedProviders = s.DeletedProviders[:32]
	}
	s.ProvidersNotice = &Notice{Tone: "warn", Message: fmt.Sprintf("Deleted provider %d and punctured subtree (known keys marked=%d).", providerID, known)}
	s.recordHistory("provider-delete", "punctured", fmt.Sprintf("Deleted provider %d", providerID), ptrInt(providerID), nil, prefix)
	return nil
}

func (s *AppState) SaveUploads(files []*multipart.FileHeader, targetSubdir string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	prefix := ""
	if strings.TrimSpace(targetSubdir) != "" {
		n, err := normalizeRelPath(targetSubdir)
		if err != nil {
			return nil, err
		}
		prefix = strings.Trim(n, "/")
	}
	saved := []string{}
	for _, header := range files {
		if header == nil || header.Filename == "" {
			continue
		}
		desired := filepath.ToSlash(header.Filename)
		if prefix != "" {
			desired = filepath.ToSlash(filepath.Join(prefix, filepath.Base(desired)))
		} else {
			desired = filepath.Base(desired)
		}
		finalRel, err := nextRelPath(s.AssetRoot, desired)
		if err != nil {
			return nil, err
		}
		abs, err := assetAbsPath(s.AssetRoot, finalRel)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			return nil, err
		}
		src, err := header.Open()
		if err != nil {
			return nil, err
		}
		dst, err := os.Create(abs)
		if err != nil {
			src.Close()
			return nil, err
		}
		_, cpErr := io.Copy(dst, src)
		_ = dst.Close()
		_ = src.Close()
		if cpErr != nil {
			return nil, cpErr
		}
		saved = append(saved, finalRel)
	}
	if len(saved) == 0 {
		return nil, errors.New("choose at least one file to upload")
	}
	s.AssetNotice = &Notice{Tone: "success", Message: fmt.Sprintf("Uploaded %d file(s).", len(saved))}
	s.recordHistory("asset-upload", "uploaded", fmt.Sprintf("Uploaded %d file(s)", len(saved)), nil, nil, "")
	return saved, nil
}

func (s *AppState) Encrypt(plaintextRelpaths []string, providerID, fileTimeID int, purpose string) ([]AssetRecord, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	if len(plaintextRelpaths) == 0 {
		return nil, nil, errors.New("select at least one cleartext file")
	}
	path, err := ggm.TagToBinaryPath(providerID, fileTimeID)
	if err != nil {
		return nil, nil, err
	}
	key, ok, err := s.Manager.GetKeyForTag(path)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, errors.New("selected key is punctured/inaccessible")
	}
	s.LastInputs = LastInputs{ProviderID: providerID, FileTimeID: fileTimeID, Purpose: strings.TrimSpace(purpose)}
	s.touchKeyDerive(providerID, fileTimeID, path, purpose)

	saved := []AssetRecord{}
	errs := []string{}
	for _, raw := range plaintextRelpaths {
		rel, err := normalizeRelPath(raw)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", raw, err))
			continue
		}
		plainAbs, err := assetAbsPath(s.AssetRoot, rel)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		blob, readErr := os.ReadFile(plainAbs)
		if readErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, readErr))
			continue
		}
		enc, encErr := encryptBlob(key, blob)
		if encErr != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, encErr))
			continue
		}
		cipherRel, err := nextCiphertextRelPath(s.AssetRoot, rel, providerID, fileTimeID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		cipherAbs, err := assetAbsPath(s.AssetRoot, cipherRel)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(cipherAbs), 0o755); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		if err := os.WriteFile(cipherAbs, enc, 0o644); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		rec := &AssetRecord{
			RecordID:          len(s.AssetRecords) + 1,
			PlaintextRelpath:  rel,
			CiphertextRelpath: cipherRel,
			ProviderID:        providerID,
			FileTimeID:        fileTimeID,
			Path:              path,
			Purpose:           strings.TrimSpace(purpose),
			CreatedAt:         nowLabel(),
			PlaintextSize:     len(blob),
			CiphertextSize:    len(enc),
		}
		s.AssetRecords = append(s.AssetRecords, rec)
		saved = append(saved, *rec)
	}
	if len(saved) == 0 {
		return nil, errs, errors.New("no file could be encrypted")
	}
	s.AssetNotice = &Notice{Tone: "success", Message: fmt.Sprintf("Encrypted %d file(s).", len(saved))}
	s.recordHistory("asset-encrypt", "encrypted", fmt.Sprintf("Encrypted %d file(s) with provider=%d,key=%d", len(saved), providerID, fileTimeID), ptrInt(providerID), ptrInt(fileTimeID), path)
	return saved, errs, nil
}

func (s *AppState) Decrypt(recordIDs []int) ([]map[string]any, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	if len(recordIDs) == 0 {
		return nil, nil, errors.New("select at least one ciphertext mapping")
	}
	index := map[int]*AssetRecord{}
	for _, rec := range s.AssetRecords {
		index[rec.RecordID] = rec
	}
	restored := []map[string]any{}
	errs := []string{}
	for _, id := range recordIDs {
		rec, ok := index[id]
		if !ok {
			errs = append(errs, fmt.Sprintf("record %d: not found", id))
			continue
		}
		key, keyOK, err := s.Manager.GetKeyForTag(rec.Path)
		if err != nil || !keyOK {
			errs = append(errs, fmt.Sprintf("record %d: key is punctured/inaccessible", id))
			continue
		}
		cipherAbs, err := assetAbsPath(s.AssetRoot, rec.CiphertextRelpath)
		if err != nil {
			errs = append(errs, fmt.Sprintf("record %d: %v", id, err))
			continue
		}
		blob, err := os.ReadFile(cipherAbs)
		if err != nil {
			errs = append(errs, fmt.Sprintf("record %d: %v", id, err))
			continue
		}
		plain, err := decryptBlob(key, blob)
		if err != nil {
			errs = append(errs, fmt.Sprintf("record %d: %v", id, err))
			continue
		}
		decRel, err := nextDecryptedRelPath(s.AssetRoot, rec.PlaintextRelpath, rec.ProviderID, rec.FileTimeID)
		if err != nil {
			errs = append(errs, fmt.Sprintf("record %d: %v", id, err))
			continue
		}
		decAbs, err := assetAbsPath(s.AssetRoot, decRel)
		if err != nil {
			errs = append(errs, fmt.Sprintf("record %d: %v", id, err))
			continue
		}
		if err := os.MkdirAll(filepath.Dir(decAbs), 0o755); err != nil {
			errs = append(errs, fmt.Sprintf("record %d: %v", id, err))
			continue
		}
		if err := os.WriteFile(decAbs, plain, 0o644); err != nil {
			errs = append(errs, fmt.Sprintf("record %d: %v", id, err))
			continue
		}
		rec.DecryptCount++
		rec.LastDecryptedAt = nowLabel()
		rec.LastDecryptedRel = decRel
		restored = append(restored, map[string]any{
			"record_id":          id,
			"ciphertext_relpath": rec.CiphertextRelpath,
			"decrypted_relpath":  decRel,
		})
	}
	if len(restored) == 0 {
		return nil, errs, errors.New("no ciphertext could be decrypted")
	}
	s.AssetNotice = &Notice{Tone: "success", Message: fmt.Sprintf("Decrypted %d mapping(s).", len(restored))}
	s.recordHistory("asset-decrypt", "decrypted", fmt.Sprintf("Decrypted %d mapping(s)", len(restored)), nil, nil, "")
	return restored, errs, nil
}

func (s *AppState) listPlaintextRows() []map[string]any {
	rows := []map[string]any{}
	_ = filepath.Walk(s.AssetRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			if strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(info.Name(), ".pke") {
			return nil
		}
		rel, relErr := filepath.Rel(s.AssetRoot, path)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		rows = append(rows, map[string]any{
			"relpath":     rel,
			"size_bytes":  info.Size(),
			"size_label":  formatBytes(info.Size()),
			"modified_at": info.ModTime().UTC().Format("2006-01-02 15:04 UTC"),
		})
		return nil
	})
	sort.Slice(rows, func(i, j int) bool { return rows[i]["relpath"].(string) < rows[j]["relpath"].(string) })
	return rows
}

func formatBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB"}
	value := float64(n)
	idx := 0
	for value >= 1024 && idx < len(units)-1 {
		value /= 1024
		idx++
	}
	if idx == 0 {
		return fmt.Sprintf("%d %s", int(value), units[idx])
	}
	return fmt.Sprintf("%.1f %s", value, units[idx])
}

func lifecycleState(mappingCount, blockedCount int) string {
	if mappingCount <= 0 {
		return "eligible"
	}
	if blockedCount <= 0 {
		return "encrypted_live"
	}
	if blockedCount < mappingCount {
		return "encrypted_partial"
	}
	return "encrypted_blocked"
}

func lifecycleLabel(state string) string {
	switch state {
	case "eligible":
		return "Eligible"
	case "encrypted_live":
		return "Encrypted (live)"
	case "encrypted_partial":
		return "Encrypted (partially blocked)"
	case "encrypted_blocked":
		return "Encrypted (fully blocked)"
	default:
		return state
	}
}

func providerRows(providers map[int]Provider, journal map[string]*KeyJournalEntry) []map[string]any {
	ids := make([]int, 0, len(providers))
	for id := range providers {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	rows := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		p := providers[id]
		prefix, _ := ggm.ProviderIDToPrefix(id)
		keys := []map[string]any{}
		for _, e := range journal {
			if e.ProviderID != id {
				continue
			}
			keys = append(keys, map[string]any{
				"provider_id":       e.ProviderID,
				"file_time_id":      e.FileTimeID,
				"path":              e.Path,
				"path_provider":     e.PathProvider,
				"path_resource":     e.PathResource,
				"description":       e.Description,
				"ever_derived":      e.EverDerived,
				"ever_punctured":    e.EverPunctured,
				"derive_count":      e.DeriveCount,
				"puncture_count":    e.PunctureCount,
				"last_derived_at":   e.LastDerivedAt,
				"last_punctured_at": e.LastPuncturedAt,
			})
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i]["file_time_id"].(int) < keys[j]["file_time_id"].(int) })
		derivedIDs := []int{}
		puncturedIDs := []int{}
		for _, k := range keys {
			if k["ever_derived"].(bool) {
				derivedIDs = append(derivedIDs, k["file_time_id"].(int))
			}
			if k["ever_punctured"].(bool) {
				puncturedIDs = append(puncturedIDs, k["file_time_id"].(int))
			}
		}
		rows = append(rows, map[string]any{
			"provider_id":     p.ProviderID,
			"name":            p.Name,
			"description":     p.Description,
			"created_at":      p.CreatedAt,
			"prefix":          prefix,
			"key_rows":        keys,
			"key_count":       len(keys),
			"derived_count":   len(derivedIDs),
			"punctured_count": len(puncturedIDs),
			"derived_ids":     derivedIDs,
			"punctured_ids":   puncturedIDs,
		})
	}
	return rows
}

func prefixIntersectsActive(prefix string, active []string) bool {
	for _, frontier := range active {
		if strings.HasPrefix(frontier, prefix) || strings.HasPrefix(prefix, frontier) {
			return true
		}
	}
	return false
}

func nodeX(prefix string, depth int, slotWidth, margin float64) float64 {
	if prefix == "" {
		leaf := 1 << depth
		return margin + (float64(leaf)*slotWidth)/2
	}
	idx, _ := parseBinary(prefix)
	left := idx * (1 << (depth - len(prefix)))
	span := 1 << (depth - len(prefix))
	center := float64(left) + float64(span)/2
	return margin + center*slotWidth
}

func parseBinary(s string) (int, error) {
	v := 0
	for _, c := range s {
		v <<= 1
		if c == '1' {
			v |= 1
		}
	}
	return v, nil
}

func (s *AppState) treeVizLocked() TreeViz {
	depth := treeDepth
	active := s.Manager.ActivePrefixes()
	derivedPrefixes := map[string]struct{}{}
	for _, entry := range s.KeyJournal {
		if !entry.EverDerived {
			continue
		}
		stop := len(entry.Path)
		if stop > depth {
			stop = depth
		}
		for d := 0; d <= stop; d++ {
			derivedPrefixes[entry.Path[:d]] = struct{}{}
		}
	}
	frontierExact := map[string]struct{}{}
	frontierProxy := map[string]struct{}{}
	for _, p := range active {
		if len(p) <= depth {
			frontierExact[p] = struct{}{}
		} else {
			frontierProxy[p[:depth]] = struct{}{}
		}
	}

	removedExact := map[string]struct{}{}
	removedProxy := map[string]struct{}{}
	if s.LastPunctureDiff != nil {
		for _, p := range s.LastPunctureDiff.Removed {
			if len(p) <= depth {
				removedExact[p] = struct{}{}
			} else {
				removedProxy[p[:depth]] = struct{}{}
			}
		}
	}

	type node struct {
		Prefix string
		Status string
	}
	statuses := map[string]string{}
	for level := 0; level <= depth; level++ {
		for idx := 0; idx < (1 << level); idx++ {
			prefix := ""
			if level > 0 {
				prefix = fmt.Sprintf("%0*b", level, idx)
			}
			possible := prefixIntersectsActive(prefix, active)
			status := "possible"
			if _, ok := removedExact[prefix]; ok {
				status = "removed"
			} else if level == depth {
				if _, ok := removedProxy[prefix]; ok {
					status = "removed_proxy"
				}
			}
			if status == "possible" {
				if _, ok := frontierExact[prefix]; ok {
					status = "frontier"
				} else if level == depth {
					if _, ok := frontierProxy[prefix]; ok {
						status = "frontier_proxy"
					}
				}
			}
			if status == "possible" {
				if !possible {
					status = "blocked"
				} else if _, ok := derivedPrefixes[prefix]; ok {
					status = "derived"
				}
			}
			statuses[prefix] = status
		}
	}

	slotWidth := 22.0
	levelHeight := 86.0
	margin := 26.0
	marginTop := 34.0
	leafSlots := 1 << depth
	width := int(margin*2 + float64(leafSlots)*slotWidth)
	height := int(marginTop + float64(depth)*levelHeight + 64)

	edges := strings.Builder{}
	for level := 0; level < depth; level++ {
		for idx := 0; idx < (1 << level); idx++ {
			parent := ""
			if level > 0 {
				parent = fmt.Sprintf("%0*b", level, idx)
			}
			px := nodeX(parent, depth, slotWidth, margin)
			py := marginTop + float64(level)*levelHeight
			for _, bit := range []string{"0", "1"} {
				child := parent + bit
				cx := nodeX(child, depth, slotWidth, margin)
				cy := marginTop + float64(level+1)*levelHeight
				edgeClass := "edge-live"
				if statuses[child] == "blocked" {
					edgeClass = "edge-blocked"
				}
				if strings.HasPrefix(statuses[child], "removed") {
					edgeClass = "edge-removed"
				}
				edges.WriteString(fmt.Sprintf(`<line class="%s" x1="%.2f" y1="%.2f" x2="%.2f" y2="%.2f" />`, edgeClass, px, py, cx, cy))
			}
		}
	}

	nodes := strings.Builder{}
	currentFrontier := 0
	blockedCount := 0
	removedCount := 0
	for level := 0; level <= depth; level++ {
		radius := 7.5
		if level == 0 {
			radius = 10
		}
		for idx := 0; idx < (1 << level); idx++ {
			prefix := ""
			if level > 0 {
				prefix = fmt.Sprintf("%0*b", level, idx)
			}
			x := nodeX(prefix, depth, slotWidth, margin)
			y := marginTop + float64(level)*levelHeight
			status := statuses[prefix]
			if status == "frontier" || status == "frontier_proxy" {
				currentFrontier++
			}
			if status == "blocked" {
				blockedCount++
			}
			if strings.HasPrefix(status, "removed") {
				removedCount++
			}
			title := "seed root"
			if prefix != "" {
				title = "prefix " + prefix
			}
			nodes.WriteString(fmt.Sprintf(`<circle class="node-%s" cx="%.2f" cy="%.2f" r="%.2f"><title>%s</title></circle>`, status, x, y, radius, title))
		}
	}

	svg := fmt.Sprintf(`<svg class="tree-svg" viewBox="0 0 %d %d" width="%d" height="%d" role="img" aria-label="Projected puncturable tree state"><style>.tree-svg{background:#fff;border:1px solid #ddd3bf;border-radius:12px}.edge-live{stroke:#8fbea3;stroke-width:1.3;opacity:.75}.edge-blocked{stroke:#d7a9a9;stroke-width:1.1;stroke-dasharray:4 4;opacity:.6}.edge-removed{stroke:#b42f2f;stroke-width:1.6;opacity:.95}.node-possible{fill:#d7f0df;stroke:#5d9a6f;stroke-width:1.3}.node-derived{fill:#ffe6ba;stroke:#c27a09;stroke-width:1.5}.node-blocked{fill:#f6d8d8;stroke:#b34f4f;stroke-width:1.2}.node-frontier{fill:#0f766e;stroke:#084a45;stroke-width:1.9}.node-frontier_proxy{fill:#8ecfc5;stroke:#0f766e;stroke-width:1.8}.node-removed{fill:#ef6a6a;stroke:#8e1a1a;stroke-width:2}.node-removed_proxy{fill:#f8b2b2;stroke:#9b1c1c;stroke-width:1.9}</style>%s%s</svg>`, width, height, width, height, edges.String(), nodes.String())

	return TreeViz{Depth: depth, CurrentFrontierCount: currentFrontier, BlockedCount: blockedCount, RemovedCount: removedCount, LastPuncture: s.LastPunctureDiff, SVG: svg}
}

func (s *AppState) snapshotLocked() map[string]any {
	providerRows := providerRows(s.Providers, s.KeyJournal)
	journalRows := make([]map[string]any, 0, len(s.KeyJournal))
	for _, entry := range s.KeyJournal {
		journalRows = append(journalRows, map[string]any{
			"provider_id":       entry.ProviderID,
			"file_time_id":      entry.FileTimeID,
			"path":              entry.Path,
			"path_provider":     entry.PathProvider,
			"path_resource":     entry.PathResource,
			"description":       entry.Description,
			"ever_derived":      entry.EverDerived,
			"ever_punctured":    entry.EverPunctured,
			"derive_count":      entry.DeriveCount,
			"puncture_count":    entry.PunctureCount,
			"last_derived_at":   entry.LastDerivedAt,
			"last_punctured_at": entry.LastPuncturedAt,
		})
	}
	sort.Slice(journalRows, func(i, j int) bool {
		if journalRows[i]["provider_id"].(int) == journalRows[j]["provider_id"].(int) {
			return journalRows[i]["file_time_id"].(int) < journalRows[j]["file_time_id"].(int)
		}
		return journalRows[i]["provider_id"].(int) < journalRows[j]["provider_id"].(int)
	})

	recordRows := []map[string]any{}
	for _, rec := range s.AssetRecords {
		_, keyOK, _ := s.Manager.GetKeyForTag(rec.Path)
		pp, pr := splitPath(rec.Path)
		recordRows = append(recordRows, map[string]any{
			"record_id":              rec.RecordID,
			"plaintext_relpath":      rec.PlaintextRelpath,
			"ciphertext_relpath":     rec.CiphertextRelpath,
			"provider_id":            rec.ProviderID,
			"file_time_id":           rec.FileTimeID,
			"path":                   rec.Path,
			"path_provider":          pp,
			"path_resource":          pr,
			"purpose":                rec.Purpose,
			"created_at":             rec.CreatedAt,
			"plaintext_size":         rec.PlaintextSize,
			"ciphertext_size":        rec.CiphertextSize,
			"is_accessible":          keyOK,
			"show_red":               !keyOK,
			"show_glow":              false,
			"decrypt_count":          rec.DecryptCount,
			"last_decrypted_at":      rec.LastDecryptedAt,
			"last_decrypted_relpath": rec.LastDecryptedRel,
		})
	}

	assetFiles := []map[string]any{}
	keyMap := map[string]map[string]any{}
	groupByPlain := map[string][]map[string]any{}
	for _, row := range recordRows {
		plain := row["plaintext_relpath"].(string)
		groupByPlain[plain] = append(groupByPlain[plain], row)

		k := fmt.Sprintf("%d:%d:%s", row["provider_id"].(int), row["file_time_id"].(int), row["path"].(string))
		bucket, ok := keyMap[k]
		if !ok {
			bucket = map[string]any{
				"provider_id":   row["provider_id"],
				"file_time_id":  row["file_time_id"],
				"path":          row["path"],
				"path_provider": row["path_provider"],
				"path_resource": row["path_resource"],
				"files":         []string{},
				"is_accessible": row["is_accessible"],
			}
			keyMap[k] = bucket
		}
		bucket["files"] = append(bucket["files"].([]string), plain)
		bucket["is_accessible"] = bucket["is_accessible"].(bool) && row["is_accessible"].(bool)
	}

	blockedTotal := 0
	glowTotal := 0
	for plain, mappings := range groupByPlain {
		sort.Slice(mappings, func(i, j int) bool {
			return mappings[i]["created_at"].(string) < mappings[j]["created_at"].(string)
		})
		blocked := 0
		for _, m := range mappings {
			if !m["is_accessible"].(bool) {
				blocked++
				blockedTotal++
			}
		}
		if blocked > 0 {
			for _, m := range mappings {
				if m["is_accessible"].(bool) {
					m["show_glow"] = true
					glowTotal++
				}
			}
		}
		assetFiles = append(assetFiles, map[string]any{
			"plaintext_relpath": plain,
			"mapping_count":     len(mappings),
			"blocked_count":     blocked,
			"mappings":          mappings,
		})
	}
	sort.Slice(assetFiles, func(i, j int) bool {
		return assetFiles[i]["plaintext_relpath"].(string) < assetFiles[j]["plaintext_relpath"].(string)
	})

	keyCards := []map[string]any{}
	for _, bucket := range keyMap {
		files := bucket["files"].([]string)
		sort.Strings(files)
		keyCards = append(keyCards, map[string]any{
			"provider_id":   bucket["provider_id"],
			"file_time_id":  bucket["file_time_id"],
			"path":          bucket["path"],
			"path_provider": bucket["path_provider"],
			"path_resource": bucket["path_resource"],
			"file_count":    len(files),
			"files":         files,
			"is_accessible": bucket["is_accessible"],
		})
	}
	sort.Slice(keyCards, func(i, j int) bool {
		if keyCards[i]["provider_id"].(int) == keyCards[j]["provider_id"].(int) {
			return keyCards[i]["file_time_id"].(int) < keyCards[j]["file_time_id"].(int)
		}
		return keyCards[i]["provider_id"].(int) < keyCards[j]["provider_id"].(int)
	})

	plainRows := s.listPlaintextRows()
	mappedByRel := map[string]map[string]any{}
	for _, af := range assetFiles {
		mappedByRel[af["plaintext_relpath"].(string)] = af
	}
	fileRows := []map[string]any{}
	for _, row := range plainRows {
		rel := row["relpath"].(string)
		mappingCount := 0
		blockedCount := 0
		if m, ok := mappedByRel[rel]; ok {
			mappingCount = m["mapping_count"].(int)
			blockedCount = m["blocked_count"].(int)
		}
		state := lifecycleState(mappingCount, blockedCount)
		row["mapping_count"] = mappingCount
		row["blocked_count"] = blockedCount
		row["lifecycle_state"] = state
		row["lifecycle_label"] = lifecycleLabel(state)
		fileRows = append(fileRows, row)
	}

	combo := []map[string]any{}
	for _, row := range journalRows {
		status := "active"
		if row["ever_punctured"].(bool) {
			status = "blocked"
		}
		combo = append(combo, map[string]any{
			"provider_id":  row["provider_id"],
			"file_time_id": row["file_time_id"],
			"status":       status,
			"label":        fmt.Sprintf("Provider %d | Key %d | %s", row["provider_id"].(int), row["file_time_id"].(int), status),
		})
	}

	activePrefixes := s.Manager.ActivePrefixes()
	tree := s.treeVizLocked()

	return map[string]any{
		"generated_at":       nowLabel(),
		"active_nodes":       s.Manager.ActiveNodeCount(),
		"active_prefixes":    activePrefixes,
		"puncture_log":       s.Manager.PunctureLog(),
		"last_puncture_diff": s.LastPunctureDiff,
		"last_action":        s.LastAction,
		"history":            s.History,
		"providers":          providerRows,
		"deleted_providers":  s.DeletedProviders,
		"key_journal":        journalRows,
		"asset_root":         s.AssetRoot,
		"state_file":         s.StateFile,
		"tree_viz":           tree,
		"assets": map[string]any{
			"mapping_count": len(recordRows),
			"blocked_count": blockedTotal,
			"glow_count":    glowTotal,
			"asset_files":   assetFiles,
			"key_cards":     keyCards,
		},
		"workflow": map[string]any{
			"asset_root": s.AssetRoot,
			"stats": map[string]any{
				"cleartext_count": len(fileRows),
				"mapping_count":   len(recordRows),
				"blocked_count":   blockedTotal,
				"glow_count":      glowTotal,
			},
			"files":             fileRows,
			"providers":         simpleProviders(providerRows),
			"key_combo_options": combo,
			"last_inputs":       s.LastInputs,
			"asset_files":       assetFiles,
			"key_cards":         keyCards,
		},
	}
}

func simpleProviders(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, p := range rows {
		out = append(out, map[string]any{"provider_id": p["provider_id"], "name": p["name"]})
	}
	return out
}

func (s *AppState) Snapshot() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshotLocked()
}

func (s *AppState) ExportStateJSON() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	payload := s.persistedPayloadLocked()
	top := map[string]any{
		"version":            payload.Version,
		"manager":            payload.Manager,
		"providers":          payload.Providers,
		"deleted_providers":  payload.DeletedProviders,
		"key_journal":        payload.KeyJournal,
		"asset_records":      payload.AssetRecords,
		"asset_root":         s.AssetRoot,
		"state_file":         s.StateFile,
		"history":            payload.History,
		"last_action":        payload.LastAction,
		"last_inputs":        payload.LastInputs,
		"last_puncture_diff": payload.LastPunctureDiff,
	}
	return json.MarshalIndent(top, "", "  ")
}

func (s *AppState) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.persistLockedNoFail()
	seed, err := ggm.GenerateMasterSeed()
	if err != nil {
		return err
	}
	mgr, err := ggm.NewManager(seed)
	if err != nil {
		return err
	}
	s.Manager = mgr
	s.Providers = defaultProviders()
	s.DeletedProviders = []DeletedProvider{}
	s.KeyJournal = map[string]*KeyJournalEntry{}
	s.AssetRecords = []*AssetRecord{}
	s.LastInputs = LastInputs{ProviderID: 42, FileTimeID: 123456, Purpose: "Demo key for provider onboarding"}
	s.LastAction = LastAction{Tone: "info", Title: "Reset complete", Body: "Lab was reset with fresh root state."}
	s.History = []HistoryItem{}
	s.LastPunctureDiff = nil
	s.recordHistory("system", "reset", "Lab was reset with fresh root state.", nil, nil, "")
	return nil
}

func (s *AppState) RemoteTokenValid(supplied, configured string) bool {
	if strings.TrimSpace(configured) == "" {
		return true
	}
	return hmac.Equal([]byte(supplied), []byte(configured))
}
