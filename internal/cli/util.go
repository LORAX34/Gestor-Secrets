package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

func fail(err error) int {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	return 1
}

func failUsage(msg string) int {
	fmt.Fprintf(os.Stderr, "usage: %s\n", msg)
	return 2
}

func printJSON(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fail(err)
	}
	return 0
}

func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}
