// Command permio is the perms.io command-line interface.
package main

import (
	"os"

	"github.com/perms-io/permio-cli/internal/cli"
)

func main() {
	os.Exit(cli.Main())
}
