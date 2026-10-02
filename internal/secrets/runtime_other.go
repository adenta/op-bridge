//go:build !linux && !(darwin && arm64)

package secrets

import (
	"fmt"
	"io"
)

func Main(args []string, input io.Reader, output, errorOutput io.Writer) int {
	fmt.Fprintln(errorOutput, "op-bridge requires Linux or macOS arm64 with a desktop 1Password app")
	return 1
}
