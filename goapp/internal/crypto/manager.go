package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const (
	ProviderBits = 7
	ResourceBits = 25
	PathBits     = ProviderBits + ResourceBits
	KeySize      = 32
)

type Manager struct {
	activeNodes       map[string][]byte
	punctureLog       []string
	puncturedPaths    map[string]struct{}
	puncturedPrefixes map[string]struct{}
}

type ExportState struct {
	ActiveNodes map[string]string `json:"active_nodes"`
	PunctureLog []string          `json:"puncture_log"`
}

func GenerateMasterSeed() ([]byte, error) {
	buf := make([]byte, KeySize)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func NewManager(masterSeed []byte) (*Manager, error) {
	if len(masterSeed) != KeySize {
		return nil, fmt.Errorf("master seed must be %d bytes", KeySize)
	}
	root := make([]byte, KeySize)
	copy(root, masterSeed)
	return &Manager{
		activeNodes:       map[string][]byte{"": root},
		punctureLog:       []string{},
		puncturedPaths:    map[string]struct{}{},
		puncturedPrefixes: map[string]struct{}{},
	}, nil
}

func validateBinary(s string, minLen, maxLen int) error {
	if len(s) < minLen || len(s) > maxLen {
		return fmt.Errorf("bitstring length must be in [%d,%d]", minLen, maxLen)
	}
	for _, c := range s {
		if c != '0' && c != '1' {
			return errors.New("bitstring must contain only 0 or 1")
		}
	}
	return nil
}

func validatePath(path string) error {
	return validateBinary(path, PathBits, PathBits)
}

func validatePrefix(prefix string) error {
	return validateBinary(prefix, 1, PathBits)
}

func deriveChild(parent []byte, bit byte) []byte {
	marker := byte(0)
	if bit == '1' {
		marker = 1
	}
	mac := hmac.New(sha256.New, parent)
	mac.Write([]byte{'G', 'G', 'M', marker})
	return mac.Sum(nil)
}

func zeroize(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func TagToBinaryPath(providerID, fileTimeID int) (string, error) {
	if providerID < 0 || providerID >= (1<<ProviderBits) {
		return "", fmt.Errorf("provider_id must be in [0,%d)", 1<<ProviderBits)
	}
	if fileTimeID < 0 || fileTimeID >= (1<<ResourceBits) {
		return "", fmt.Errorf("file_time_id must be in [0,%d)", 1<<ResourceBits)
	}
	value := (providerID << ResourceBits) | fileTimeID
	return fmt.Sprintf("%032b", value), nil
}

func ProviderIDToPrefix(providerID int) (string, error) {
	if providerID < 0 || providerID >= (1<<ProviderBits) {
		return "", fmt.Errorf("provider_id must be in [0,%d)", 1<<ProviderBits)
	}
	return fmt.Sprintf("%07b", providerID), nil
}

func (m *Manager) cloneSeed(prefix string) []byte {
	seed := m.activeNodes[prefix]
	out := make([]byte, len(seed))
	copy(out, seed)
	return out
}

func (m *Manager) findCovering(path string) (string, bool) {
	for depth := len(path); depth >= 0; depth-- {
		prefix := path[:depth]
		if _, ok := m.activeNodes[prefix]; ok {
			return prefix, true
		}
	}
	return "", false
}

func (m *Manager) ActiveNodeCount() int {
	return len(m.activeNodes)
}

func (m *Manager) ActivePrefixes() []string {
	prefixes := make([]string, 0, len(m.activeNodes))
	for p := range m.activeNodes {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool {
		if len(prefixes[i]) == len(prefixes[j]) {
			return prefixes[i] < prefixes[j]
		}
		return len(prefixes[i]) < len(prefixes[j])
	})
	return prefixes
}

func (m *Manager) PunctureLog() []string {
	out := make([]string, len(m.punctureLog))
	copy(out, m.punctureLog)
	return out
}

func (m *Manager) ExportPunctureLogJSON() string {
	buf, _ := json.Marshal(m.punctureLog)
	return string(buf)
}

func (m *Manager) GetKeyForTag(path string) ([]byte, bool, error) {
	if err := validatePath(path); err != nil {
		return nil, false, err
	}
	cover, ok := m.findCovering(path)
	if !ok {
		return nil, false, nil
	}
	current := m.cloneSeed(cover)
	for i := len(cover); i < len(path); i++ {
		next := deriveChild(current, path[i])
		zeroize(current)
		current = next
	}
	return current, true, nil
}

func (m *Manager) Puncture(path string) (bool, error) {
	if err := validatePath(path); err != nil {
		return false, err
	}
	if _, exists := m.puncturedPaths[path]; exists {
		return false, nil
	}
	for prefix := range m.puncturedPrefixes {
		if len(prefix) <= len(path) && path[:len(prefix)] == prefix {
			return false, nil
		}
	}

	cover, ok := m.findCovering(path)
	if !ok {
		m.puncturedPaths[path] = struct{}{}
		m.punctureLog = append(m.punctureLog, path)
		return false, nil
	}

	current := m.activeNodes[cover]
	delete(m.activeNodes, cover)
	for depth := len(cover); depth < PathBits; depth++ {
		bit := path[depth]
		siblingBit := byte('0')
		if bit == '0' {
			siblingBit = '1'
		}
		siblingKey := deriveChild(current, siblingBit)
		siblingPrefix := path[:depth] + string(siblingBit)
		m.activeNodes[siblingPrefix] = siblingKey

		next := deriveChild(current, bit)
		zeroize(current)
		current = next
	}
	zeroize(current)

	m.puncturedPaths[path] = struct{}{}
	m.punctureLog = append(m.punctureLog, path)
	return true, nil
}

func (m *Manager) PuncturePrefix(prefix string) (bool, error) {
	if err := validatePrefix(prefix); err != nil {
		return false, err
	}
	if len(prefix) == PathBits {
		return m.Puncture(prefix)
	}
	if _, exists := m.puncturedPrefixes[prefix]; exists {
		return false, nil
	}
	for p := range m.puncturedPrefixes {
		if len(p) <= len(prefix) && prefix[:len(p)] == p {
			return false, nil
		}
	}

	changed := false
	cover, ok := m.findCovering(prefix)
	if ok {
		changed = true
		current := m.activeNodes[cover]
		delete(m.activeNodes, cover)

		for depth := len(cover); depth < len(prefix); depth++ {
			bit := prefix[depth]
			siblingBit := byte('0')
			if bit == '0' {
				siblingBit = '1'
			}
			siblingKey := deriveChild(current, siblingBit)
			siblingPrefix := prefix[:depth] + string(siblingBit)
			m.activeNodes[siblingPrefix] = siblingKey

			next := deriveChild(current, bit)
			zeroize(current)
			current = next
		}
		zeroize(current)
	}

	for node, seed := range m.activeNodes {
		if len(node) >= len(prefix) && node[:len(prefix)] == prefix {
			changed = true
			zeroize(seed)
			delete(m.activeNodes, node)
		}
	}

	m.puncturedPrefixes[prefix] = struct{}{}
	m.punctureLog = append(m.punctureLog, prefix)
	return changed, nil
}

func (m *Manager) PunctureProvider(providerID int) (bool, error) {
	prefix, err := ProviderIDToPrefix(providerID)
	if err != nil {
		return false, err
	}
	return m.PuncturePrefix(prefix)
}

func (m *Manager) ExportState() ExportState {
	out := ExportState{ActiveNodes: map[string]string{}, PunctureLog: m.PunctureLog()}
	for prefix, seed := range m.activeNodes {
		out.ActiveNodes[prefix] = hex.EncodeToString(seed)
	}
	return out
}

func FromState(state ExportState) (*Manager, error) {
	baseSeed := make([]byte, KeySize)
	m, _ := NewManager(baseSeed)
	m.activeNodes = map[string][]byte{}
	m.punctureLog = append([]string(nil), state.PunctureLog...)
	m.puncturedPaths = map[string]struct{}{}
	m.puncturedPrefixes = map[string]struct{}{}

	for prefix, hexSeed := range state.ActiveNodes {
		if prefix != "" {
			if err := validatePrefix(prefix); err != nil {
				return nil, err
			}
		}
		seed, err := hex.DecodeString(hexSeed)
		if err != nil || len(seed) != KeySize {
			return nil, errors.New("invalid active seed")
		}
		m.activeNodes[prefix] = seed
	}
	for _, bitstring := range m.punctureLog {
		if len(bitstring) == PathBits {
			m.puncturedPaths[bitstring] = struct{}{}
		} else {
			m.puncturedPrefixes[bitstring] = struct{}{}
		}
	}
	return m, nil
}
