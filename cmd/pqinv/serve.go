package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/angga-22/pqinv/internal/baseline"
	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/scan"
	"github.com/angga-22/pqinv/internal/serve"
)

var (
	flagServeConfig   string
	flagServeInterval time.Duration
	flagServeListen   string
	flagServeBaseline string
)

const minServeInterval = 10 * time.Second

var serveCmd = &cobra.Command{
	Use:   "serve --config targets.yaml",
	Short: "Scan targets on a schedule and expose readiness as Prometheus metrics",
	Long: `Runs every target in the config file on an interval and serves:

  /metrics      Prometheus exposition: pqinv_score, pqinv_findings,
                pqinv_target_unreachable, pqinv_new_findings_total,
                pqinv_certificate_expiry_timestamp_seconds, ...
  /report.json  the latest report in the --format json schema (a valid
                --baseline input)
  /healthz      200 once the first scan has completed

Each scan is compared with the one before it (or with --baseline for
the first scan); findings that were not there are counted in
pqinv_new_findings_total and logged. Alert on increase() of that
counter and on pqinv_target_unreachable == 1.

  pqinv serve --config targets.yaml --interval 1h --listen :9465`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagServeConfig == "" {
			return fmt.Errorf("serve requires --config")
		}
		if err := validateServeFlags(flagServeInterval, flagServeListen); err != nil {
			return err
		}
		targets, err := loadTargets(flagServeConfig)
		if err != nil {
			return err
		}
		var bl *baseline.Baseline
		if flagServeBaseline != "" {
			f, err := os.Open(flagServeBaseline)
			if err != nil {
				return fmt.Errorf("--baseline: %w", err)
			}
			bl, err = baseline.Load(f)
			f.Close()
			if err != nil {
				return fmt.Errorf("--baseline %s: %w", flagServeBaseline, err)
			}
		}
		probes, err := buildProbes()
		if err != nil {
			return err
		}
		classifier, err := classify.New()
		if err != nil {
			return fmt.Errorf("load classification rules: %w", err)
		}

		logger := log.New(os.Stderr, "pqinv: ", log.LstdFlags|log.LUTC)
		srv := &serve.Server{
			Runner:     &scan.Runner{Probes: probes, Concurrency: flagConcurrency},
			Classifier: classifier,
			Targets:    targets,
			Interval:   flagServeInterval,
			Version:    version,
			Baseline:   bl,
			Log:        logger,
		}
		httpSrv := &http.Server{
			Addr:              flagServeListen,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
		return runServe(cmd.Context(), srv, httpSrv, logger)
	},
}

func validateServeFlags(interval time.Duration, listen string) error {
	if interval < minServeInterval {
		return fmt.Errorf("--interval must be at least %s, got %s", minServeInterval, interval)
	}
	if listen == "" {
		return fmt.Errorf("--listen must not be empty")
	}
	return nil
}

// runServe runs the scan loop and the HTTP server until ctx is done,
// then shuts the listener down cleanly. Ctrl-C therefore ends in-flight
// handshakes and open scrapes rather than killing the process mid-scan.
func runServe(ctx context.Context, srv *serve.Server, httpSrv *http.Server, logger *log.Logger) error {
	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		err := srv.Run(ctx)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	})
	g.Go(func() error {
		logger.Printf("listening on %s (interval %s, %d targets)", httpSrv.Addr, srv.Interval, len(srv.Targets))
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	g.Go(func() error {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	})
	return g.Wait()
}

func init() {
	serveCmd.Flags().StringVar(&flagServeConfig, "config", "", "targets file (yaml)")
	serveCmd.Flags().DurationVar(&flagServeInterval, "interval", time.Hour, "time between scans (minimum 10s)")
	serveCmd.Flags().StringVar(&flagServeListen, "listen", ":9465", "address to serve /metrics on")
	serveCmd.Flags().StringVar(&flagServeBaseline, "baseline", "", "previous --format json report the first scan is compared against")
	addProbeFlags(serveCmd.Flags())
	rootCmd.AddCommand(serveCmd)
}
