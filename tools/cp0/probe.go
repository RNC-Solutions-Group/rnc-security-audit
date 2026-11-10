// CP0 language probe: identical naive literal-byte search to probe.rs.
// This is NOT the RNC detection engine, a credential rule, or a production benchmark.
package main

import (
	"bytes"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: probe file")
		os.Exit(64)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	needle := []byte("RNC_SYNTH_KEY_")
	count := 0
	for i := 0; i+len(needle) <= len(data); i++ {
		if bytes.Equal(data[i:i+len(needle)], needle) {
			count++
		}
	}
	fmt.Println(count)
}
