//go:build !linux

package secrets

import (
	"fmt"
	"io"
)

func Main(args []string, input io.Reader, output, errorOutput io.Writer) int {
	fmt.Fprintln(errorOutput, "op-bridge requires Linux with systemd and a desktop 1Password app")
	return 1
}
