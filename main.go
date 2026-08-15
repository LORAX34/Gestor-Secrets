package main

import (
	"os"

	"github.com/ivanperez/cli-secret/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
