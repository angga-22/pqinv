// Package saml inventories SAML 2.0 metadata: the certificates each
// entity signs and encrypts with, and every XML Signature / XML
// Encryption algorithm the metadata names. SAML is where rsa-sha1 and
// RSA key transport still live in 2026, and nothing else in the PQ
// tooling looks at it.
package saml

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/angga-22/pqinv/internal/model"
	"github.com/angga-22/pqinv/internal/probe/certs"
)

const (
	defaultTimeout = 10 * time.Second
	maxBody        = 8 << 20 // federation aggregates run to several MB
)

// Probe implements probe.Probe for SAML metadata. The target is either
// an http(s) URL or a local file path.
type Probe struct {
	Timeout   time.Duration
	Client    *http.Client
	UserAgent string
}

func (p *Probe) Name() string { return "saml" }

func (p *Probe) Scan(ctx context.Context, target string) ([]model.CryptoAsset, error) {
	var data []byte
	var err error
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		data, err = p.get(ctx, target)
	} else {
		data, err = os.ReadFile(target)
	}
	if err != nil {
		return nil, fmt.Errorf("read SAML metadata: %w", err)
	}
	return Parse(target, data)
}

// algorithmURIs maps XML Signature / XML Encryption algorithm identifiers
// to the vocabulary rules.yaml speaks. A URI not listed here is reported
// under its fragment so it surfaces as Unknown rather than disappearing.
var algorithmURIs = map[string]struct {
	alg   string
	usage model.Usage
}{
	// signatures
	"http://www.w3.org/2000/09/xmldsig#rsa-sha1":             {"RSA-SHA1", model.UsageSignature},
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":             {"DSA-SHA1", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-md5":         {"RSA-MD5", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":      {"RSA-SHA256", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384":      {"RSA-SHA384", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512":      {"RSA-SHA512", model.UsageSignature},
	"http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1": {"RSA-PSS-SHA256", model.UsageSignature},
	"http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1": {"RSA-PSS-SHA384", model.UsageSignature},
	"http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1": {"RSA-PSS-SHA512", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1":      {"ECDSA-SHA1", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256":    {"ECDSA-SHA256", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384":    {"ECDSA-SHA384", model.UsageSignature},
	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512":    {"ECDSA-SHA512", model.UsageSignature},
	"http://www.w3.org/2009/xmldsig11#dsa-sha256":            {"DSA-SHA256", model.UsageSignature},
	"http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519":   {"Ed25519", model.UsageSignature},
	// digests
	"http://www.w3.org/2000/09/xmldsig#sha1":        {"SHA-1", model.UsageHash},
	"http://www.w3.org/2001/04/xmldsig-more#md5":    {"MD5", model.UsageHash},
	"http://www.w3.org/2001/04/xmlenc#sha256":       {"SHA-256", model.UsageHash},
	"http://www.w3.org/2001/04/xmldsig-more#sha384": {"SHA-384", model.UsageHash},
	"http://www.w3.org/2001/04/xmlenc#sha512":       {"SHA-512", model.UsageHash},
	// key transport / agreement
	"http://www.w3.org/2001/04/xmlenc#rsa-1_5":        {"RSA1_5", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p": {"RSA-OAEP", model.UsageEncryption},
	"http://www.w3.org/2009/xmlenc11#rsa-oaep":        {"RSA-OAEP", model.UsageEncryption},
	"http://www.w3.org/2009/xmlenc11#ECDH-ES":         {"ECDH-ES", model.UsageEncryption},
	"http://www.w3.org/2009/xmlenc11#dh-es":           {"DH-ES", model.UsageEncryption},
	// block ciphers and key wrapping
	"http://www.w3.org/2001/04/xmlenc#tripledes-cbc": {"3DES-CBC", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#aes128-cbc":    {"AES-128-CBC", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#aes192-cbc":    {"AES-192-CBC", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#aes256-cbc":    {"AES-256-CBC", model.UsageEncryption},
	"http://www.w3.org/2009/xmlenc11#aes128-gcm":     {"AES-128-GCM", model.UsageEncryption},
	"http://www.w3.org/2009/xmlenc11#aes192-gcm":     {"AES-192-GCM", model.UsageEncryption},
	"http://www.w3.org/2009/xmlenc11#aes256-gcm":     {"AES-256-GCM", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#kw-tripledes":  {"3DES-KW", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#kw-aes128":     {"AES-128-KW", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#kw-aes192":     {"AES-192-KW", model.UsageEncryption},
	"http://www.w3.org/2001/04/xmlenc#kw-aes256":     {"AES-256-KW", model.UsageEncryption},
}

// elementUsage is the fallback usage for an algorithm URI we cannot map,
// keyed by the element that named it.
var elementUsage = map[string]model.Usage{
	"SignatureMethod":  model.UsageSignature,
	"SigningMethod":    model.UsageSignature,
	"DigestMethod":     model.UsageHash,
	"EncryptionMethod": model.UsageEncryption,
}

var roleElements = map[string]bool{
	"IDPSSODescriptor": true, "SPSSODescriptor": true, "AttributeAuthorityDescriptor": true,
	"AuthnAuthorityDescriptor": true, "PDPDescriptor": true, "RoleDescriptor": true,
}

type walker struct {
	target   string
	entityID string
	role     string
	use      string
	entities int
	certN    int
	seen     map[string]bool
	assets   []model.CryptoAsset
}

// Parse turns metadata bytes into assets. It walks the token stream
// rather than binding a schema so it is indifferent to namespace
// prefixes, element order, and whether the document is one
// EntityDescriptor or a federation's EntitiesDescriptor.
func Parse(target string, data []byte) ([]model.CryptoAsset, error) {
	w := &walker{target: target, seen: map[string]bool{}}
	dec := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse SAML metadata: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch name := t.Name.Local; {
			case name == "EntityDescriptor":
				w.entityID = attr(t, "entityID")
				w.entities++
				w.certN = 0
			case roleElements[name]:
				w.role = name
			case name == "KeyDescriptor":
				w.use = attr(t, "use")
			case name == "X509Certificate":
				var b64 string
				if err := dec.DecodeElement(&b64, &t); err != nil {
					return nil, fmt.Errorf("parse SAML metadata: %w", err)
				}
				w.addCert(b64)
			case elementUsage[name] != "":
				w.addAlgorithm(name, attr(t, "Algorithm"))
			}
		case xml.EndElement:
			switch name := t.Name.Local; {
			case name == "KeyDescriptor":
				w.use = ""
			case roleElements[name]:
				w.role = ""
			case name == "EntityDescriptor":
				w.entityID = ""
			}
		}
	}
	if w.entities == 0 {
		return nil, fmt.Errorf("%s: no EntityDescriptor found — not SAML metadata", target)
	}
	return w.assets, nil
}

func (w *walker) location() string {
	if w.entityID != "" {
		return w.entityID
	}
	return w.target
}

func (w *walker) addCert(b64 string) {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(b64), ""))
	var cert *x509.Certificate
	if err == nil {
		cert, err = x509.ParseCertificate(der)
	}
	if err != nil {
		// Surfaced, never dropped: a KeyDescriptor we cannot read is a
		// key we cannot vouch for.
		w.assets = append(w.assets, model.CryptoAsset{
			Source:    "saml",
			Location:  w.location(),
			Usage:     model.UsageSignature,
			Algorithm: "Unknown",
			Metadata: map[string]string{
				"kind": "certificate", "role": w.role, "use": w.use, "entity_id": w.entityID,
				"error": "unparseable X509Certificate: " + err.Error(),
			},
		})
		return
	}

	// SAML: use="signing", use="encryption", or absent meaning both.
	var usages []model.Usage
	switch w.use {
	case "signing":
		usages = []model.Usage{model.UsageSignature}
	case "encryption":
		usages = []model.Usage{model.UsageEncryption}
	default:
		usages = []model.Usage{model.UsageSignature, model.UsageEncryption}
	}
	fp := sha256.Sum256(cert.Raw)
	for _, usage := range usages {
		key := "cert|" + w.entityID + "|" + string(usage) + "|" + hex.EncodeToString(fp[:])
		if w.seen[key] {
			continue
		}
		w.seen[key] = true
		loc := fmt.Sprintf("%s cert#%d", w.location(), w.certN)
		for _, a := range certs.Assets("saml", loc, usage, cert) {
			a.Metadata["role"] = w.role
			a.Metadata["use"] = w.use
			a.Metadata["entity_id"] = w.entityID
			a.Metadata["fingerprint_sha256"] = hex.EncodeToString(fp[:])
			w.assets = append(w.assets, a)
		}
	}
	w.certN++
}

func (w *walker) addAlgorithm(element, uri string) {
	if uri == "" {
		return
	}
	alg, usage := "", elementUsage[element]
	if m, ok := algorithmURIs[uri]; ok {
		alg, usage = m.alg, m.usage
	} else if i := strings.LastIndexAny(uri, "#/"); i >= 0 && i < len(uri)-1 {
		alg = uri[i+1:]
	} else {
		alg = uri
	}
	key := "alg|" + w.entityID + "|" + element + "|" + alg
	if w.seen[key] {
		return
	}
	w.seen[key] = true
	w.assets = append(w.assets, model.CryptoAsset{
		Source:    "saml",
		Location:  w.location(),
		Usage:     usage,
		Algorithm: alg,
		Metadata: map[string]string{
			"kind":      "saml-algorithm",
			"element":   element,
			"uri":       uri,
			"role":      w.role,
			"entity_id": w.entityID,
		},
	})
}

func attr(el xml.StartElement, name string) string {
	for _, a := range el.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (p *Probe) get(ctx context.Context, url string) ([]byte, error) {
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	ua := p.UserAgent
	if ua == "" {
		ua = "pqinv"
	}
	req.Header.Set("User-Agent", ua)

	client := p.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}
