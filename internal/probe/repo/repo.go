package repo

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/angga-22/pqinv/internal/model"
)

//go:embed patterns.yaml
var patternsYAML []byte

const (
	maxFileSize = 2 << 20 // skip files >2MB: generated bundles, not source
	sniffLen    = 8192    // bytes checked for NUL to detect binaries
)

var skipDirs = map[string]bool{
	"vendor": true, "node_modules": true, "dist": true, "build": true,
	"target": true, "venv": true, "__pycache__": true,
}

// Documentation and markup mention algorithms without using them — a
// README saying "we migrated off MD5" is not a finding. Config formats
// (yaml/json/toml) stay in scope: an IdP realm export or TLS config
// naming RS256 is real, live crypto configuration.
var skipExts = map[string]bool{
	".html": true, ".htm": true, ".md": true, ".markdown": true,
	".txt": true, ".rst": true, ".adoc": true, ".svg": true,
	".csv": true, ".lock": true,
}

type pattern struct {
	name      string
	re        *regexp.Regexp
	algorithm string
	usage     model.Usage
}

type Probe struct {
	patterns []pattern
}

func New() (*Probe, error) {
	var doc struct {
		Patterns []struct {
			Name      string      `yaml:"name"`
			Regex     string      `yaml:"regex"`
			Algorithm string      `yaml:"algorithm"`
			Usage     model.Usage `yaml:"usage"`
		} `yaml:"patterns"`
	}
	if err := yaml.Unmarshal(patternsYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse patterns.yaml: %w", err)
	}
	p := &Probe{}
	for _, raw := range doc.Patterns {
		re, err := regexp.Compile(raw.Regex)
		if err != nil {
			return nil, fmt.Errorf("pattern %s: %w", raw.Name, err)
		}
		if raw.Usage == "" {
			return nil, fmt.Errorf("pattern %s: usage is required", raw.Name)
		}
		p.patterns = append(p.patterns, pattern{
			name: raw.Name, re: re, algorithm: raw.Algorithm, usage: raw.Usage,
		})
	}
	if len(p.patterns) == 0 {
		return nil, fmt.Errorf("patterns.yaml contains no patterns")
	}
	return p, nil
}

func (p *Probe) Name() string { return "repo" }

func (p *Probe) Scan(ctx context.Context, target string) ([]model.CryptoAsset, error) {
	root, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", target)
	}

	var assets []model.CryptoAsset
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, don't abort
		}
		if d.IsDir() {
			if path != root && (skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if skipExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if fi, err := d.Info(); err != nil || fi.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil || isBinary(data) {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		assets = append(assets, p.scanFile(rel, data)...)
		return nil
	})
	if walkErr != nil {
		return assets, walkErr
	}
	return assets, nil
}

func (p *Probe) scanFile(rel string, data []byte) []model.CryptoAsset {
	var assets []model.CryptoAsset
	seen := map[string]bool{}

	for lineNo, line := range strings.Split(string(data), "\n") {
		for _, pat := range p.patterns {
			match := pat.re.FindString(line)
			if match == "" {
				continue
			}
			algorithm := pat.algorithm
			if algorithm == "" {
				algorithm = match
			}
			location := fmt.Sprintf("%s:%d", rel, lineNo+1)
			if seen[location+"|"+algorithm] {
				continue
			}
			seen[location+"|"+algorithm] = true

			snippet := strings.TrimSpace(line)
			if len(snippet) > 120 {
				snippet = snippet[:120] + "…"
			}
			assets = append(assets, model.CryptoAsset{
				Source:    "repo",
				Location:  location,
				Usage:     pat.usage,
				Algorithm: algorithm,
				Metadata: map[string]string{
					"kind":    "source-pattern",
					"pattern": pat.name,
					"snippet": snippet,
				},
			})
		}
	}
	return assets
}

func isBinary(data []byte) bool {
	n := min(len(data), sniffLen)
	return bytes.IndexByte(data[:n], 0) >= 0
}
