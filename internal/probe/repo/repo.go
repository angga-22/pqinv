package repo

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
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

	// IgnoreFile, read from the scanned root, lists paths the probe must
	// not scan: one glob per line in Go path.Match syntax, `#` comments
	// and blank lines ignored. A pattern without a slash is matched
	// against the base name of every entry (so `*_test.go` works at any
	// depth); a pattern with a slash is matched against the full
	// slash-separated path relative to the root. A trailing `/` restricts
	// the pattern to directories, which are then pruned whole.
	IgnoreFile = ".pqinvignore"
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
	ignores, err := loadIgnore(root)
	if err != nil {
		return nil, err
	}

	var assets []model.CryptoAsset
	walkErr := filepath.WalkDir(root, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entry: skip, don't abort
		}
		if name == root {
			return nil
		}
		rel, err := filepath.Rel(root, name)
		if err != nil {
			rel = name
		}
		if d.IsDir() {
			if skipDirs[d.Name()] || strings.HasPrefix(d.Name(), ".") || ignored(ignores, rel, true) {
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if skipExts[strings.ToLower(filepath.Ext(name))] || ignored(ignores, rel, false) {
			return nil
		}
		if fi, err := d.Info(); err != nil || fi.Size() > maxFileSize {
			return nil
		}
		data, err := os.ReadFile(name)
		if err != nil || isBinary(data) {
			return nil
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

// loadIgnore reads the root's IgnoreFile. A missing file means no
// excludes; a malformed pattern is an error, because a typo that
// silently excludes nothing (or everything) is the wrong failure mode.
func loadIgnore(root string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(root, IgnoreFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", IgnoreFile, err)
	}
	var globs []string
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := path.Match(strings.TrimSuffix(line, "/"), ""); err != nil {
			return nil, fmt.Errorf("%s line %d: bad pattern %q: %w", IgnoreFile, i+1, line, err)
		}
		globs = append(globs, line)
	}
	return globs, nil
}

func ignored(globs []string, rel string, isDir bool) bool {
	if len(globs) == 0 {
		return false
	}
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	for _, g := range globs {
		dirOnly := strings.HasSuffix(g, "/")
		if dirOnly && !isDir {
			continue
		}
		g = strings.TrimSuffix(g, "/")
		if ok, _ := path.Match(g, rel); ok {
			return true
		}
		if !strings.Contains(g, "/") {
			if ok, _ := path.Match(g, base); ok {
				return true
			}
		}
	}
	return false
}

func isBinary(data []byte) bool {
	n := min(len(data), sniffLen)
	return bytes.IndexByte(data[:n], 0) >= 0
}
