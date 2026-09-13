// Command pqinv is the CLI entry point. All printing and os.Exit lives
// in cmd/; internal/ stays reusable by the v2 Kubernetes operator.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// Ctrl-C cancels the context, which unwinds in-flight handshakes
	// cleanly instead of killing the process mid-scan.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := rootCmd.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "pqinv:", err)
		os.Exit(1)
	}
}
