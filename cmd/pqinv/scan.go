package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/angga-22/pqinv/internal/baseline"
	"github.com/angga-22/pqinv/internal/classify"
	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe"
	"github.com/angga-22/pqinv/internal/probe/oidc"
	"github.com/angga-22/pqinv/internal/probe/repo"
	"github.com/angga-22/pqinv/internal/probe/saml"
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
	flagCAFile      string
	flagInsecure    bool
	flagBaseline    string

	// gateBaseline is loaded in PersistentPreRunE so a bad --baseline
	// fails before any scanning happens.
	gateBaseline *baseline.Baseline
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
		if flagFailOn != "" {
			if _, ok := parseUrgency(flagFailOn); !ok {
				return fmt.Errorf("--fail-on must be high|medium|low, got %q", flagFailOn)
			}
		}
		if flagBaseline != "" {
			if flagFailOn == "" {
				return fmt.Errorf("--baseline only makes sense with --fail-on")
			}
			f, err := os.Open(flagBaseline)
			if err != nil {
				return fmt.Errorf("--baseline: %w", err)
			}
			defer f.Close()
			if gateBaseline, err = baseline.Load(f); err != nil {
				return fmt.Errorf("--baseline %s: %w", flagBaseline, err)
			}
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
	Short: "Inventory an OIDC issuer: discovery document, JWKS keys, and the issuer's TLS",
	Long: `Fetches {issuer}/.well-known/openid-configuration and its JWKS, then
classifies every published key, every advertised signing and encryption
algorithm, and the TLS endpoint the issuer and JWKS are served from —
the channel tokens are harvested on. Works against any OIDC provider —
Keycloak, Auth0, Entra, Okta:

  pqinv scan oidc https://id.example.com/realms/main

Issuers behind a private CA: --ca-file ca.pem adds a PEM bundle to the
trust store; --insecure skips verification entirely (lab realms only).`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingle(cmd, "oidc", args[0])
	},
}

var scanSAMLCmd = &cobra.Command{
	Use:   "saml <metadata-url|file>",
	Short: "Inventory SAML 2.0 metadata: signing/encryption certificates and XML algorithms",
	Long: `Reads SAML 2.0 metadata (an IdP, an SP, or a federation aggregate)
from a URL or a local file and classifies every certificate each entity
signs and encrypts with, plus every SignatureMethod, DigestMethod,
SigningMethod and EncryptionMethod the metadata names:

  pqinv scan saml https://idp.example.org/idp/shibboleth
  pqinv scan saml ./sp-metadata.xml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runSingle(cmd, "saml", args[0])
	},
}

var scanRepoCmd = &cobra.Command{
	Use:   "repo <directory>",
	Short: "Statically scan a source tree for crypto imports and algorithm literals",
	Long: `Walks the tree and matches each line against the embedded crypto
patterns (imports, JOSE algorithm literals, committed private keys).
A ` + repo.IgnoreFile + ` file in the directory excludes paths, one glob per
line (Go path.Match syntax; no slash matches the base name anywhere,
trailing slash means directories only).`,
	Args: cobra.ExactArgs(1),
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
    - probe: saml
      target: https://idp.example.org/idp/shibboleth
    - probe: repo
      target: ./my-service`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagConfig == "" {
			return fmt.Errorf("scan all requires --config")
		}
		targets, err := loadTargets(flagConfig)
		if err != nil {
			return err
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
		results := runner.Run(cmd.Context(), targets)

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

// loadTargets parses a targets.yaml. An empty list is an error: a CI
// gate that scans nothing must not pass.
func loadTargets(path string) ([]scan.Target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Targets []scan.Target `yaml:"targets"`
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("%s lists no targets", path)
	}
	for i, t := range cfg.Targets {
		if t.Probe == "" || t.Target == "" {
			return nil, fmt.Errorf("%s: target %d needs both probe and target", path, i+1)
		}
	}
	return cfg.Targets, nil
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
	return checkFailOn(flagFailOn, reports, gateBaseline)
}

func parseUrgency(s string) (model.Urgency, bool) {
	switch strings.ToLower(s) {
	case "high":
		return model.UrgencyHigh, true
	case "medium":
		return model.UrgencyMedium, true
	case "low":
		return model.UrgencyLow, true
	}
	return "", false
}

// checkFailOn is the CI gate: exit non-zero when findings at or above
// the threshold exist. With a baseline, only findings that are new since
// that report count — regressions, not inherited debt. Unreachable
// targets always trip the gate — "we couldn't check" must never read as
// "all clear".
func checkFailOn(failOn string, reports []report.TargetReport, bl *baseline.Baseline) error {
	if failOn == "" {
		return nil
	}
	urgency, ok := parseUrgency(failOn)
	if !ok {
		return fmt.Errorf("--fail-on must be high|medium|low, got %q", failOn)
	}
	threshold := urgencyRank[urgency]

	unreachable := 0
	for _, rep := range reports {
		if rep.Error != "" {
			unreachable++
		}
	}

	var candidates []baseline.Finding
	if bl != nil {
		candidates = bl.NewFindings(reports)
	} else {
		for _, rep := range reports {
			for _, v := range rep.Verdicts {
				candidates = append(candidates, baseline.Finding{Probe: rep.Probe, Target: rep.Target, Verdict: v})
			}
		}
	}
	var tripped []baseline.Finding
	for _, f := range candidates {
		if urgencyRank[f.Verdict.Urgency] >= threshold {
			tripped = append(tripped, f)
		}
	}
	if len(tripped) == 0 && unreachable == 0 {
		return nil
	}

	var b strings.Builder
	if bl != nil {
		fmt.Fprintf(&b, "fail-on %s vs baseline: %d new findings at or above threshold, %d unreachable targets",
			strings.ToLower(failOn), len(tripped), unreachable)
	} else {
		fmt.Fprintf(&b, "fail-on %s: %d findings at or above threshold, %d unreachable targets",
			strings.ToLower(failOn), len(tripped), unreachable)
	}
	const show = 10
	for i, f := range tripped {
		if i == show {
			fmt.Fprintf(&b, "\n  … and %d more", len(tripped)-show)
			break
		}
		fmt.Fprintf(&b, "\n  %s · %s · %s %s [%s] at %s",
			f.Probe, f.Target, f.Verdict.Urgency, f.Verdict.Asset.Algorithm, f.Verdict.Asset.Usage, f.Verdict.Asset.Location)
	}
	return fmt.Errorf("%s", b.String())
}

func buildProbes() (map[string]probe.Probe, error) {
	repoProbe, err := repo.New()
	if err != nil {
		return nil, fmt.Errorf("load repo patterns: %w", err)
	}
	httpClient, err := newHTTPClient(flagCAFile, flagInsecure)
	if err != nil {
		return nil, err
	}
	ua := "pqinv/" + version
	tlsProbe := &tlsprobe.Probe{Timeout: flagTimeout}
	return map[string]probe.Probe{
		"tls":  tlsProbe,
		"oidc": &oidc.Probe{Timeout: flagTimeout, Client: httpClient, UserAgent: ua, TLS: tlsProbe},
		"saml": &saml.Probe{Timeout: flagTimeout, Client: httpClient, UserAgent: ua},
		"repo": repoProbe,
	}, nil
}

// newHTTPClient builds the client the OIDC probe fetches with. Identity
// infrastructure usually lives behind a private CA, so --ca-file appends
// a PEM bundle to the system roots; --insecure skips verification for
// lab boxes. The TLS probe is unaffected: it never verifies, because it
// inventories what a server presents rather than deciding to trust it.
func newHTTPClient(caFile string, insecure bool) (*http.Client, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure} //nolint:gosec // opt-in via --insecure
	if caFile != "" {
		pemBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("--ca-file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pemBytes) {
			return nil, fmt.Errorf("--ca-file %s: no PEM certificates found", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	return &http.Client{Transport: transport}, nil
}

func init() {
	scanCmd.PersistentFlags().DurationVar(&flagTimeout, "timeout", 10*time.Second, "per-request timeout")
	scanCmd.PersistentFlags().StringVar(&flagFormat, "format", "pretty", "output format: pretty|json|cbom")
	scanCmd.PersistentFlags().StringVar(&flagOut, "out", "", "write report to file instead of stdout")
	scanCmd.PersistentFlags().IntVar(&flagConcurrency, "concurrency", 8, "max concurrent targets (scan all)")
	scanCmd.PersistentFlags().StringVar(&flagFailOn, "fail-on", "", "exit 1 if findings at or above this urgency exist: high|medium|low")
	scanCmd.PersistentFlags().StringVar(&flagBaseline, "baseline", "", "previous --format json report; with --fail-on, only findings new since it count")
	scanCmd.PersistentFlags().StringVar(&flagCAFile, "ca-file", "", "PEM bundle of extra CA certificates trusted when fetching OIDC documents")
	scanCmd.PersistentFlags().BoolVar(&flagInsecure, "insecure", false, "skip TLS certificate verification when fetching OIDC documents")
	scanAllCmd.Flags().StringVar(&flagConfig, "config", "", "targets file (yaml)")
	scanCmd.AddCommand(scanTLSCmd, scanOIDCCmd, scanSAMLCmd, scanRepoCmd, scanAllCmd)
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
