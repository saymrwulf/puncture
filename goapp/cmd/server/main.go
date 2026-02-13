package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"puncture-go/internal/server"
)

func main() {
	host := flag.String("host", getenv("PUNCTURE_HOST", "0.0.0.0"), "bind host")
	port := flag.Int("port", getenvInt("PUNCTURE_PORT", 9122), "bind port")
	assetRoot := flag.String("asset-root", getenv("PUNCTURE_ASSET_ROOT", "./assets"), "asset root directory")
	flag.Parse()

	addr := server.ParseAddr(*host, *port)
	log.Printf("starting puncture-go server on %s", addr)
	if err := server.Run(addr, *assetRoot); err != nil {
		log.Fatalf("server failed: %v", err)
	}
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
