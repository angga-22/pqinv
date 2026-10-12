package model

import "sort"

type Usage string

const (
	UsageKeyExchange Usage = "KeyExchange"
	UsageSignature   Usage = "Signature"
	UsageEncryption  Usage = "Encryption"
	UsageHash        Usage = "Hash"
	UsageProtocol    Usage = "Protocol"
)

type Class string

const (
	ClassVulnerable    Class = "Vulnerable"    // broken by Shor's algorithm
	ClassHybrid        Class = "Hybrid"        // classical + PQ combined (e.g. X25519MLKEM768)
	ClassPQSafe        Class = "PQSafe"        // pure post-quantum (ML-KEM, ML-DSA)
	ClassWeakClassical Class = "WeakClassical" // broken today, quantum aside (MD5, RSA<2048)
	ClassAcceptable    Class = "Acceptable"    // fine for now (AES-128 vs Grover)
	ClassUnknown       Class = "Unknown"       // surfaced loudly, never silently dropped
)

type Urgency string

const (
	UrgencyHigh   Urgency = "High"
	UrgencyMedium Urgency = "Medium"
	UrgencyLow    Urgency = "Low"
	UrgencyNone   Urgency = "None"
)

type CryptoAsset struct {
	Source    string            `json:"source"`   // "tls" | "oidc" | "saml" | "repo"
	Location  string            `json:"location"` // "id.example.com:443", jwks URL, "file.go:42"
	Usage     Usage             `json:"usage"`
	Algorithm string            `json:"algorithm"` // normalized: "X25519", "RSA", "ES256", "ML-KEM-768"…
	KeyBits   int               `json:"key_bits,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type Verdict struct {
	Asset      CryptoAsset `json:"asset"`
	Class      Class       `json:"class"`
	Urgency    Urgency     `json:"urgency"`
	Rationale  string      `json:"rationale"`
	Migration  string      `json:"migration"`
	References []string    `json:"references,omitempty"`
}

func SortAssets(assets []CryptoAsset) {
	sort.Slice(assets, func(i, j int) bool {
		a, b := assets[i], assets[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		if a.Usage != b.Usage {
			return a.Usage < b.Usage
		}
		return a.Algorithm < b.Algorithm
	})
}
