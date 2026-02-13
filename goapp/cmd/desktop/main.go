//go:build darwin && cgo && desktop

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	webview "github.com/webview/webview_go"

	"puncture-go/internal/server"
)

func main() {
	defaultRoot := defaultAssetRoot()
	host := flag.String("host", getenv("PUNCTURE_HOST", "127.0.0.1"), "bind host")
	port := flag.Int("port", getenvInt("PUNCTURE_PORT", 9122), "bind port")
	assetRoot := flag.String("asset-root", getenv("PUNCTURE_ASSET_ROOT", defaultRoot), "asset root directory")
	flag.Parse()

	addr := server.ParseAddr(*host, *port)
	srv, _, err := server.Start(addr, *assetRoot)
	if err != nil {
		log.Fatalf("failed to start embedded server: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	url := fmt.Sprintf("http://%s", addr)
	w := webview.New(true)
	defer w.Destroy()
	w.SetTitle("Puncture Go")
	w.SetSize(1280, 860, webview.HintNone)
	w.Navigate(url)
	maybeLaunchSimulatorCompanion(filepath.Base(os.Args[0]))
	w.Run()
}

func defaultAssetRoot() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "./assets"
	}
	return filepath.Join(home, "Library", "Application Support", "PunctureGo", "assets")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var parsed int
	if _, err := fmt.Sscanf(v, "%d", &parsed); err != nil {
		return fallback
	}
	return parsed
}
