package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/angga-22/pqinv/internal/model"
)

var urgencySections = []struct {
	urgency model.Urgency
	label   string
	color   lipgloss.Color
}{
	{model.UrgencyHigh, "HIGH — act now", lipgloss.Color("9")},
	{model.UrgencyMedium, "MEDIUM — plan the migration", lipgloss.Color("11")},
	{model.UrgencyLow, "LOW — keep an eye on it", lipgloss.Color("12")},
	{model.UrgencyNone, "OK — no action needed", lipgloss.Color("10")},
}

var classMarks = map[model.Class]string{
	model.ClassVulnerable:    "✗",
	model.ClassWeakClassical: "✗",
	model.ClassUnknown:       "?",
	model.ClassAcceptable:    "•",
	model.ClassHybrid:        "✓",
	model.ClassPQSafe:        "✓",
}

func Pretty(w io.Writer, reports []TargetReport) error {
	r := lipgloss.NewRenderer(w)
	title := r.NewStyle().Bold(true)
	dim := r.NewStyle().Faint(true)
	errStyle := r.NewStyle().Bold(true).Foreground(lipgloss.Color("9"))

	var b strings.Builder
	for _, rep := range reports {
		label := rep.Target
		if rep.Probe != "" {
			label = rep.Probe + " · " + rep.Target
		}
		fmt.Fprintf(&b, "\n%s  %s\n", title.Render("pqinv · PQ readiness"), dim.Render(label))

		if rep.Error != "" {
			fmt.Fprintf(&b, "  %s\n", errStyle.Render("unreachable: "+rep.Error))
			continue
		}

		fmt.Fprintf(&b, "%s %s\n",
			gradeStyle(r, rep.Grade).Render(fmt.Sprintf(" %s  %d/100 ", rep.Grade, rep.Score)),
			dim.Render(summaryLine(rep.Verdicts)))

		for _, s := range urgencySections {
			var group []model.Verdict
			for _, v := range rep.Verdicts {
				if v.Urgency == s.urgency {
					group = append(group, v)
				}
			}
			if len(group) == 0 {
				continue
			}
			section := r.NewStyle().Bold(true).Foreground(s.color)
			fmt.Fprintf(&b, "\n%s\n", section.Render(fmt.Sprintf("%s (%d)", s.label, len(group))))
			for _, v := range group {
				writeVerdict(&b, r, s.color, dim, v)
			}
		}
		b.WriteString("\n")
	}

	_, err := io.WriteString(w, b.String())
	return err
}

func gradeStyle(r *lipgloss.Renderer, grade string) lipgloss.Style {
	color := lipgloss.Color("10") // A/B green
	switch grade {
	case "C":
		color = lipgloss.Color("11")
	case "D", "F":
		color = lipgloss.Color("9")
	}
	return r.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(color)
}

func summaryLine(verdicts []model.Verdict) string {
	counts := map[model.Urgency]int{}
	for _, v := range verdicts {
		counts[v.Urgency]++
	}
	return fmt.Sprintf("%d findings · %d high · %d medium · %d low · %d ok",
		len(verdicts),
		counts[model.UrgencyHigh], counts[model.UrgencyMedium],
		counts[model.UrgencyLow], counts[model.UrgencyNone])
}

func writeVerdict(b *strings.Builder, r *lipgloss.Renderer, color lipgloss.Color, dim lipgloss.Style, v model.Verdict) {
	name := v.Asset.Algorithm
	if v.Asset.KeyBits > 0 {
		name = fmt.Sprintf("%s (%d bit)", name, v.Asset.KeyBits)
	}
	head := r.NewStyle().Bold(true).Foreground(color).Render(classMarks[v.Class] + " " + name)
	note := fmt.Sprintf("[%s] %s", v.Class, contextNote(v.Asset))
	fmt.Fprintf(b, "  %s %s\n", head, dim.Render(note))

	if v.Urgency == model.UrgencyNone {
		return
	}
	fmt.Fprintf(b, "     %s\n", dim.Render(v.Rationale))
	if v.Migration != "" {
		arrow := r.NewStyle().Bold(true).Foreground(color).Render("→")
		fmt.Fprintf(b, "     %s %s\n", arrow, r.NewStyle().Bold(true).Render(v.Migration))
	}
}

func contextNote(a model.CryptoAsset) string {
	parts := []string{usageLabel(a.Usage), a.Location}
	switch a.Metadata["kind"] {
	case "certificate":
		parts = append(parts, a.Metadata["subject"], "expires "+a.Metadata["not_after"])
	case "jwk":
		if kid := a.Metadata["kid"]; kid != "" {
			parts = append(parts, "kid "+kid)
		}
	case "advertised-signing-alg":
		parts = append(parts, "advertised capability")
	case "key-exchange-group", "cipher-suite":
		if v := a.Metadata["tls_version"]; v != "" {
			parts = append(parts, v)
		}
	case "source-pattern":
		if s := a.Metadata["snippet"]; s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " · ")
}

func usageLabel(u model.Usage) string {
	switch u {
	case model.UsageKeyExchange:
		return "key exchange"
	case model.UsageSignature:
		return "signature"
	case model.UsageEncryption:
		return "encryption"
	case model.UsageHash:
		return "hash"
	case model.UsageProtocol:
		return "protocol"
	}
	return string(u)
}
