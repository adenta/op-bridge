//go:build darwin && arm64

package secrets

import (
	"context"
	"fmt"
)

func runPhone(Config) error { return fmt.Errorf("phone sessions require a Linux execution host") }
func phoneDispatch(context.Context, Config, Desktop, Request) Response {
	return notStarted("phone sessions require a Linux execution host")
}
