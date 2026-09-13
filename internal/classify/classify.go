// Package classify is the rules engine: it turns CryptoAssets into
// Verdicts by matching them against the embedded rules.yaml. The
// knowledge base is data, not code — adding an algorithm is a YAML edit
// plus a table test. The classifier knows nothing about where an asset
// came from; that separation is what lets one rule set serve the TLS,
// OIDC, and repo probes alike.
package classify

import (
	"fmt"
	"path"
	"slices"

	"gopkg.in/yaml.v3"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/rules"
)

type rule struct {
	Name  string `yaml:"name"`
	Match struct {
		Algorithms   []string      `yaml:"algorithms"`
		Usages       []model.Usage `yaml:"usages"`
		KeyBitsBelow int           `yaml:"key_bits_below"`
	} `yaml:"match"`
	Class      model.Class   `yaml:"class"`
	Urgency    model.Urgency `yaml:"urgency"`
	Rationale  string        `yaml:"rationale"`
	Migration  string        `yaml:"migration"`
	References []string      `yaml:"references"`
}

func (r *rule) matches(a model.CryptoAsset) bool {
	if len(r.Match.Usages) > 0 && !slices.Contains(r.Match.Usages, a.Usage) {
		return false
	}
	if r.Match.KeyBitsBelow > 0 && !(a.KeyBits > 0 && a.KeyBits < r.Match.KeyBitsBelow) {
		return false
	}
	for _, pat := range r.Match.Algorithms {
		if ok, _ := path.Match(pat, a.Algorithm); ok {
			return true
		}
	}
	return false
}

type Classifier struct {
	rules []rule
}

func New() (*Classifier, error) {
	return NewFromYAML(rules.YAML)
}

var (
	validClasses = []model.Class{
		model.ClassVulnerable, model.ClassHybrid, model.ClassPQSafe,
		model.ClassWeakClassical, model.ClassAcceptable, model.ClassUnknown,
	}
	validUrgencies = []model.Urgency{
		model.UrgencyHigh, model.UrgencyMedium, model.UrgencyLow, model.UrgencyNone,
	}
)

func NewFromYAML(data []byte) (*Classifier, error) {
	var doc struct {
		Rules []rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse rules: %w", err)
	}
	if len(doc.Rules) == 0 {
		return nil, fmt.Errorf("rule set is empty")
	}
	for _, r := range doc.Rules {
		if r.Name == "" {
			return nil, fmt.Errorf("rule with class %q has no name", r.Class)
		}
		if len(r.Match.Algorithms) == 0 {
			return nil, fmt.Errorf("rule %s: match.algorithms is empty", r.Name)
		}
		for _, pat := range r.Match.Algorithms {
			if _, err := path.Match(pat, ""); err != nil {
				return nil, fmt.Errorf("rule %s: bad pattern %q: %w", r.Name, pat, err)
			}
		}
		if !slices.Contains(validClasses, r.Class) {
			return nil, fmt.Errorf("rule %s: unknown class %q", r.Name, r.Class)
		}
		if !slices.Contains(validUrgencies, r.Urgency) {
			return nil, fmt.Errorf("rule %s: unknown urgency %q", r.Name, r.Urgency)
		}
	}
	return &Classifier{rules: doc.Rules}, nil
}

func (c *Classifier) Classify(a model.CryptoAsset) model.Verdict {
	for i := range c.rules {
		r := &c.rules[i]
		if r.matches(a) {
			return model.Verdict{
				Asset:      a,
				Class:      r.Class,
				Urgency:    r.Urgency,
				Rationale:  r.Rationale,
				Migration:  r.Migration,
				References: r.References,
			}
		}
	}
	return model.Verdict{
		Asset:     a,
		Class:     model.ClassUnknown,
		Urgency:   model.UrgencyMedium,
		Rationale: "Not in the rule set. Unknowns get surfaced, never dropped — an inventory that hides what it can't name isn't an inventory.",
		Migration: "Identify the algorithm and add a rule to rules/rules.yaml.",
	}
}

func (c *Classifier) ClassifyAll(assets []model.CryptoAsset) []model.Verdict {
	verdicts := make([]model.Verdict, 0, len(assets))
	for _, a := range assets {
		verdicts = append(verdicts, c.Classify(a))
	}
	return verdicts
}
