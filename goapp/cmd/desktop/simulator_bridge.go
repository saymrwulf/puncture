//go:build darwin && cgo && desktop

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultSimBundleID = "com.puncture.emergency"

type simctlDevice struct {
	UDID        string `json:"udid"`
	Name        string `json:"name"`
	State       string `json:"state"`
	IsAvailable bool   `json:"isAvailable"`
}

type simctlDevicesPayload struct {
	Devices map[string][]simctlDevice `json:"devices"`
}

func maybeLaunchSimulatorCompanion(desktopProcess string) {
	if !envBool("PUNCTURE_WITH_SIMULATOR", true) {
		log.Printf("sim companion: disabled by PUNCTURE_WITH_SIMULATOR")
		return
	}
	go func() {
		if err := launchSimulatorCompanion(desktopProcess); err != nil {
			log.Printf("sim companion: %v", err)
		}
	}()
}

func launchSimulatorCompanion(desktopProcess string) error {
	appPath := resolveSimulatorCompanionAppPath()
	if appPath == "" {
		return errors.New("iOS simulator companion app not found; build the DMG again to bundle it")
	}
	bundleID := getenv("PUNCTURE_SIM_BUNDLE_ID", defaultSimBundleID)
	preferred := getenv("PUNCTURE_SIM_DEVICE", "iPhone 17 Pro")

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()

	udid, name, err := pickSimulatorDevice(ctx, preferred)
	if err != nil {
		return err
	}
	log.Printf("sim companion: using device %s (%s)", name, udid)

	if _, err := runCommand(ctx, "open", "-a", "Simulator", "--args", "-CurrentDeviceUDID", udid); err != nil {
		// Fallback for older Simulator CLI behavior.
		if _, retryErr := runCommand(ctx, "open", "-a", "Simulator"); retryErr != nil {
			return fmt.Errorf("failed to open Simulator: %w", retryErr)
		}
	}
	if out, err := runCommand(ctx, "xcrun", "simctl", "boot", udid); err != nil {
		if !strings.Contains(strings.ToLower(out), "booted") {
			return fmt.Errorf("failed to boot simulator: %w", err)
		}
	}
	if _, err := runCommand(ctx, "xcrun", "simctl", "bootstatus", udid, "-b"); err != nil {
		return fmt.Errorf("failed waiting for simulator boot: %w", err)
	}
	if _, err := runCommand(ctx, "xcrun", "simctl", "install", udid, appPath); err != nil {
		return fmt.Errorf("failed to install companion app into simulator: %w", err)
	}
	launchOut, err := runCommand(ctx, "xcrun", "simctl", "launch", udid, bundleID)
	if err != nil {
		return fmt.Errorf("failed to launch companion app (%s): %w", bundleID, err)
	}
	if strings.TrimSpace(launchOut) != "" {
		log.Printf("sim companion: %s", strings.TrimSpace(launchOut))
	}

	// Give both apps time to draw their first windows before window arrangement.
	go func() {
		time.Sleep(1300 * time.Millisecond)
		_ = arrangeDesktopWithSimulator(desktopProcess)
		time.Sleep(1800 * time.Millisecond)
		_ = arrangeDesktopWithSimulator(desktopProcess)
	}()
	return nil
}

func resolveSimulatorCompanionAppPath() string {
	candidates := []string{}
	if explicit := strings.TrimSpace(os.Getenv("PUNCTURE_IOS_SIM_APP")); explicit != "" {
		candidates = append(candidates, explicit)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates,
			filepath.Clean(filepath.Join(filepath.Dir(exe), "..", "Resources", "EmergencyPuncture.app")),
			filepath.Clean(filepath.Join(filepath.Dir(exe), "..", "..", "..", "ios", "build-ios", "Build", "Products", "Debug-iphonesimulator", "EmergencyPuncture.app")),
		)
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, "ios", "build-ios", "Build", "Products", "Debug-iphonesimulator", "EmergencyPuncture.app"),
			filepath.Join(cwd, "..", "ios", "build-ios", "Build", "Products", "Debug-iphonesimulator", "EmergencyPuncture.app"),
			filepath.Join(cwd, "goapp", "ios", "build-ios", "Build", "Products", "Debug-iphonesimulator", "EmergencyPuncture.app"),
		)
	}
	seen := map[string]struct{}{}
	for _, cand := range candidates {
		if cand == "" {
			continue
		}
		abs, err := filepath.Abs(cand)
		if err == nil {
			cand = abs
		}
		if _, ok := seen[cand]; ok {
			continue
		}
		seen[cand] = struct{}{}
		info, statErr := os.Stat(cand)
		if statErr == nil && info.IsDir() {
			return cand
		}
	}
	return ""
}

func pickSimulatorDevice(ctx context.Context, preferredName string) (string, string, error) {
	out, err := runCommand(ctx, "xcrun", "simctl", "list", "devices", "available", "-j")
	if err != nil {
		return "", "", fmt.Errorf("failed to query simulator devices: %w", err)
	}
	var payload simctlDevicesPayload
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		return "", "", fmt.Errorf("failed to parse simulator list: %w", err)
	}

	type candidate struct {
		Runtime string
		Device  simctlDevice
	}
	candidates := make([]candidate, 0, 24)
	runtimes := make([]string, 0, len(payload.Devices))
	for runtime := range payload.Devices {
		if strings.Contains(strings.ToLower(runtime), "ios") {
			runtimes = append(runtimes, runtime)
		}
	}
	sort.Slice(runtimes, func(i, j int) bool { return runtimes[i] > runtimes[j] })
	for _, runtime := range runtimes {
		devs := append([]simctlDevice(nil), payload.Devices[runtime]...)
		sort.Slice(devs, func(i, j int) bool {
			if devs[i].State == devs[j].State {
				return devs[i].Name < devs[j].Name
			}
			return devs[i].State == "Booted"
		})
		for _, dev := range devs {
			if !dev.IsAvailable || dev.UDID == "" || dev.Name == "" {
				continue
			}
			candidates = append(candidates, candidate{Runtime: runtime, Device: dev})
		}
	}
	if len(candidates) == 0 {
		return "", "", errors.New("no available iOS simulator device found")
	}

	preferredName = strings.TrimSpace(preferredName)
	lowerPreferred := strings.ToLower(preferredName)
	pick := func(match func(candidate) bool) (candidate, bool) {
		for _, c := range candidates {
			if match(c) {
				return c, true
			}
		}
		return candidate{}, false
	}

	if preferredName != "" {
		if c, ok := pick(func(c candidate) bool {
			return strings.EqualFold(c.Device.Name, preferredName) && strings.EqualFold(c.Device.State, "Booted")
		}); ok {
			return c.Device.UDID, c.Device.Name, nil
		}
		if c, ok := pick(func(c candidate) bool {
			return strings.EqualFold(c.Device.Name, preferredName)
		}); ok {
			return c.Device.UDID, c.Device.Name, nil
		}
		if c, ok := pick(func(c candidate) bool {
			return strings.Contains(strings.ToLower(c.Device.Name), lowerPreferred)
		}); ok {
			return c.Device.UDID, c.Device.Name, nil
		}
	}
	if c, ok := pick(func(c candidate) bool {
		return strings.EqualFold(c.Device.State, "Booted") && strings.Contains(strings.ToLower(c.Device.Name), "iphone")
	}); ok {
		return c.Device.UDID, c.Device.Name, nil
	}
	if c, ok := pick(func(c candidate) bool {
		return strings.Contains(strings.ToLower(c.Device.Name), "iphone")
	}); ok {
		return c.Device.UDID, c.Device.Name, nil
	}
	return candidates[0].Device.UDID, candidates[0].Device.Name, nil
}

func arrangeDesktopWithSimulator(desktopProcess string) error {
	desktopProcess = strings.TrimSpace(desktopProcess)
	if desktopProcess == "" {
		desktopProcess = "Puncture"
	}
	desktopProcess = strings.ReplaceAll(desktopProcess, `"`, "")
	script := fmt.Sprintf(`
set topInset to 28
tell application "Finder"
	set b to bounds of window of desktop
end tell
set screenW to item 3 of b
set screenH to item 4 of b
set leftW to (screenW * 62 / 100)
tell application "System Events"
	if exists process "%[1]s" then
		tell process "%[1]s"
			if (count of windows) > 0 then
				set position of window 1 to {0, topInset}
				set size of window 1 to {leftW, screenH - topInset}
			end if
		end tell
	end if
	if exists process "Simulator" then
		tell process "Simulator"
			if (count of windows) > 0 then
				set position of window 1 to {leftW, topInset}
				set size of window 1 to {screenW - leftW, screenH - topInset}
			end if
		end tell
	end if
	if exists process "%[1]s" then
		set frontmost of process "%[1]s" to true
	end if
end tell
`, desktopProcess)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if _, err := runCommand(ctx, "osascript", "-e", script); err != nil {
		log.Printf("sim companion: could not auto-arrange windows (%v)", err)
	}
	return nil
}

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		if text == "" {
			return "", err
		}
		return text, fmt.Errorf("%w: %s", err, text)
	}
	return text, nil
}

func envBool(key string, fallback bool) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	default:
		return fallback
	}
}
