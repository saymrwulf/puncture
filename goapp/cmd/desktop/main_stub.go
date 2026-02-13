//go:build !(darwin && cgo && desktop)

package main

import "fmt"

func main() {
	fmt.Println("desktop build requires: darwin + cgo + -tags desktop")
}
