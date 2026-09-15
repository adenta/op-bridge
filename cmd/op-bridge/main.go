package main

import (
	"github.com/adenta/op-bridge/internal/secrets"
	"os"
)

func main() { os.Exit(secrets.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }
