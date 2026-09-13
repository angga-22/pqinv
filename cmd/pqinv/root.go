package main

import (
	"runtime/debug"

	"github.com/spf13/cobra"
)

// version is stamped by goreleaser via -ldflags "-X main.version=…".
// Binaries built by `go install …@v0.1.0` skip ldflags, so fall back to
// the module version Go embeds in the build info.
var version = "dev"

var rootCmd = &cobra.Command{
	Use:   "pqinv",
	Short: "Post-quantum crypto inventory",
	Long: `pqinv inventories the cryptography a system actually uses — TLS
handshakes, certificate chains, OIDC/JWKS signing keys, source code —
and classifies each finding against the NIST post-quantum migration
timeline (FIPS 203/204, NIST IR 8547).`,
	// Runtime errors (unreachable host, bad handshake) shouldn't dump
	// usage text; main() prints the error once.
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	if version == "dev" {
		if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			version = bi.Main.Version
		}
	}
	rootCmd.Version = version
}
