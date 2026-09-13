package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe"
	"github.com/angga-22/pqinv/internal/probe/oidc"
	"github.com/angga-22/pqinv/internal/probe/repo"
	"github.com/angga-22/pqinv/internal/probe/tlsprobe"
	"github.com/angga-22/pqinv/internal/report"
	"github.com/angga-22/pqinv/internal/scan"
	"github.com/angga-22/pqinv/internal/score"
)

var (
	flagTimeout     time.Duration
	flagFormat      string
	flagOut         string
	flagConfig      string
	flagConcurrency int
	flagFailOn      string
)

var urgencyRank = map[model.Urgency]int{
	model.UrgencyLow:    1,
	model.UrgencyMedium: 2,
	model.UrgencyHigh:   3,
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan targets and inventory their cryptography",
	// Validate flag values before any network traffic happens — a typo
	// in --format shouldn't cost a full scan.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		switch flagFormat {
		case "pretty", "json", "cbom":
		default:
			return fmt.Errorf("--format must be pretty|json|cbom, got %q", flagFormat)
		}
		switch strings.ToLower(flagFailOn) {
		case "", "low", "medium", "high":
		default:
			return fmt.Errorf("--fail-on must be high|medium|low, got %q", flagFailOn)
		}
		return nil
	},
}

var scanTLSCmd = &cobra.Command{
	Use:   "tls <host[:port]>",
	Short: "Enumerate a TLS endpoint: key-exchange groups, protocol versions, certificate chain",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingle(cmd, "tls", normalizeTarget(args[0]))
	},
}

var scanOIDCCmd = &cobra.Command{
	Use:   "oidc <issuer-url>",
	Short: "Inventory an OIDC issuer: discovery document + JWKS signing/encryption keys",
	Long: `Fetches {issuer}/.well-known/openid-configuration and its JWKS,
then classifies every published key and every advertised signing
algorithm. Works against any OIDC provider — Keycloak, Auth0, Entra,
Okta:

  pqinv scan oidc https://id.example.com/realms/main`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingle(cmd, "oidc", args[0])
	},
}

var scanRepoCmd = &cobra.Command{
	Use:   "repo <directory>",
	Short: "Statically scan a source tree for crypto imports and algorithm literals",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingle(cmd, "repo", args[0])
	},
}

var scanAllCmd = &cobra.Command{
	Use:   "all --config targets.yaml",
	Short: "Scan many targets from a config file, one report",
	Long: `Config format:

  targets:
    - probe: tls
      target: id.example.com:443
    - probe: oidc
      target: https://id.example.com/realms/main
    - probe: repo
      target: ./my-service`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagConfig == "" {
			return fmt.Errorf("scan all requires --config")
		}
		data, err := os.ReadFile(flagConfig)
		if err != nil {
			return err
		}
		var cfg struct {
			Targets []scan.Target `yaml:"targets"`
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", flagConfig, err)
		}
		if len(cfg.Targets) == 0 {
			return fmt.Errorf("%s lists no targets", flagConfig)
		}

		probes, err := buildProbes()
		if err != nil {
			return err
		}
		classifier, err := classify.New()
		if err != nil {
			return fmt.Errorf("load classification rules: %w", err)
		}

		runner := &scan.Runner{Probes: probes, Concurrency: flagConcurrency}
		results := runner.Run(cmd.Context(), cfg.Targets)

		reports := make([]report.TargetReport, 0, len(results))
		for _, res := range results {
			if res.Err != nil {
				reports = append(reports, report.TargetReport{
					Probe: res.Target.Probe, Target: res.Target.Target,
					Error: res.Err.Error(),
				})
				continue
			}
			reports = append(reports, buildReport(classifier, res.Target.Probe, res.Target.Target, res.Assets))
		}
		return emit(reports)
	},
}

// runSingle is one target through the whole pipeline: probe → sort →
// classify → correlate → score → report. A single-target scan treats an
// unreachable target as a hard error; only `scan all` degrades.
func runSingle(cmd *cobra.Command, probeName, target string) error {
	probes, err := buildProbes()
	if err != nil {
		return err
	}
	assets, err := probes[probeName].Scan(cmd.Context(), target)
	if err != nil {
		return err
	}
	classifier, err := classify.New()
	if err != nil {
		return fmt.Errorf("load classification rules: %w", err)
	}
	return emit([]report.TargetReport{buildReport(classifier, probeName, target, assets)})
}

func buildReport(classifier *classify.Classifier, probeName, target string, assets []model.CryptoAsset) report.TargetReport {
	model.SortAssets(assets)
	verdicts := classify.Correlate(classifier.ClassifyAll(assets))
	sc := score.Compute(verdicts)
	return report.TargetReport{
		Probe: probeName, Target: target,
		Score: sc.Score, Grade: sc.Grade,
		Verdicts: verdicts,
	}
}

func emit(reports []report.TargetReport) error {
	out, closeOut, err := openOutput()
	if err != nil {
		return err
	}
	defer closeOut()

	switch flagFormat {
	case "pretty":
		err = report.Pretty(out, reports)
	case "json":
		err = report.JSON(out, version, reports)
	case "cbom":
		err = report.CBOM(out, version, reports)
	}
	if err != nil {
		return err
	}
	return checkFailOn(reports)
}

// checkFailOn is the CI gate: exit non-zero when findings at or above
// the threshold exist. Unreachable targets always trip the gate — "we
// couldn't check" must never read as "all clear".
func checkFailOn(reports []report.TargetReport) error {
	if flagFailOn == "" {
		return nil
	}
	threshold := urgencyRank[model.Urgency(strings.ToUpper(flagFailOn[:1])+strings.ToLower(flagFailOn[1:]))]

	findings, unreachable := 0, 0
	for _, rep := range reports {
		if rep.Error != "" {
			unreachable++
		}
		for _, v := range rep.Verdicts {
			if urgencyRank[v.Urgency] >= threshold {
				findings++
			}
		}
	}
	if findings > 0 || unreachable > 0 {
		return fmt.Errorf("fail-on %s: %d findings at or above threshold, %d unreachable targets",
			strings.ToLower(flagFailOn), findings, unreachable)
	}
	return nil
}

func buildProbes() (map[string]probe.Probe, error) {
	repoProbe, err := repo.New()
	if err != nil {
		return nil, fmt.Errorf("load repo patterns: %w", err)
	}
	return map[string]probe.Probe{
		"tls":  &tlsprobe.Probe{Timeout: flagTimeout},
		"oidc": &oidc.Probe{Timeout: flagTimeout},
		"repo": repoProbe,
	}, nil
}

func init() {
	scanCmd.PersistentFlags().DurationVar(&flagTimeout, "timeout", 10*time.Second, "per-request timeout")
	scanCmd.PersistentFlags().StringVar(&flagFormat, "format", "pretty", "output format: pretty|json|cbom")
	scanCmd.PersistentFlags().StringVar(&flagOut, "out", "", "write report to file instead of stdout")
	scanCmd.PersistentFlags().IntVar(&flagConcurrency, "concurrency", 8, "max concurrent targets (scan all)")
	scanCmd.PersistentFlags().StringVar(&flagFailOn, "fail-on", "", "exit 1 if findings at or above this urgency exist: high|medium|low")
	scanAllCmd.Flags().StringVar(&flagConfig, "config", "", "targets file (yaml)")
	scanCmd.AddCommand(scanTLSCmd, scanOIDCCmd, scanRepoCmd, scanAllCmd)
	rootCmd.AddCommand(scanCmd)
}

// normalizeTarget defaults the port to 443, handling IPv6 literals via
// the net helpers instead of naive string splitting.
func normalizeTarget(arg string) string {
	if _, _, err := net.SplitHostPort(arg); err != nil {
		return net.JoinHostPort(arg, "443")
	}
	return arg
}

func openOutput() (io.Writer, func(), error) {
	if flagOut == "" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.Create(flagOut)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}
