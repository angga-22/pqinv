package saml

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/angga-22/pqinv/internal/model"
)

func certB64(t *testing.T, key any, pub any, sigAlg x509.SignatureAlgorithm) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{CommonName: "saml-test"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: sigAlg,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	// Real metadata wraps the base64 across lines; the parser must cope.
	b := base64.StdEncoding.EncodeToString(der)
	var lines []string
	for len(b) > 64 {
		lines, b = append(lines, b[:64]), b[64:]
	}
	return strings.Join(append(lines, b), "\n")
}

// metadata is shaped like a Shibboleth/ADFS IdP: a signed document using
// rsa-sha1, an RSA signing cert, a separate EC encryption cert with the
// usual EncryptionMethod list, and the algsupport extension.
func metadata(t *testing.T) string {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing := certB64(t, rsaKey, &rsaKey.PublicKey, x509.SHA1WithRSA)
	enc := certB64(t, ecKey, &ecKey.PublicKey, x509.ECDSAWithSHA256)
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    xmlns:alg="urn:oasis:names:tc:SAML:metadata:algsupport"
    entityID="https://idp.example.org/idp/shibboleth">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
      <ds:Reference URI="">
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
  <md:Extensions>
    <alg:SigningMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
    <alg:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
  </md:Extensions>
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>
%s
      </ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>%s</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
      <md:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
      <md:EncryptionMethod Algorithm="http://example.org/vendor#frobnicate"/>
    </md:KeyDescriptor>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>
`, signing, enc)
}

// index keys assets by kind/usage/algorithm: a SHA-256 certificate
// signature and a SHA-256 DigestMethod are two different facts.
func index(assets []model.CryptoAsset) map[string]model.CryptoAsset {
	m := map[string]model.CryptoAsset{}
	for _, a := range assets {
		m[a.Metadata["kind"]+"/"+string(a.Usage)+"/"+a.Algorithm] = a
	}
	return m
}

func TestParseIdPMetadata(t *testing.T) {
	assets, err := Parse("idp.xml", []byte(metadata(t)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got := index(assets)

	for _, a := range assets {
		if a.Source != "saml" {
			t.Errorf("source = %s", a.Source)
		}
		if a.Metadata["entity_id"] != "https://idp.example.org/idp/shibboleth" {
			t.Errorf("entity_id missing on %+v", a)
		}
	}

	// Signing cert: RSA key, and its SHA-1 signature is a separate finding.
	sig, ok := got["certificate/Signature/RSA"]
	if !ok {
		t.Fatal("RSA signing certificate not reported")
	}
	if sig.KeyBits != 2048 || sig.Metadata["role"] != "IDPSSODescriptor" || sig.Metadata["use"] != "signing" || sig.Metadata["kind"] != "certificate" {
		t.Errorf("signing cert = %+v", sig)
	}
	if _, ok := got["certificate-signature/Hash/SHA-1"]; !ok {
		t.Error("the signing cert's SHA-1 signature must be its own finding")
	}
	if _, ok := got["saml-algorithm/Hash/SHA-1"]; !ok {
		t.Error("the sha1 DigestMethod must be reported")
	}

	// Encryption cert: EC key under encryption usage.
	enc, ok := got["certificate/Encryption/ECDSA P-256"]
	if !ok {
		t.Fatal("EC encryption certificate not reported")
	}
	if enc.Metadata["use"] != "encryption" {
		t.Errorf("encryption cert use = %q", enc.Metadata["use"])
	}

	// Algorithms by URI, with the unmapped one surfaced by its fragment.
	for _, want := range []string{
		"Signature/RSA-SHA1", "Signature/RSA-SHA256", "Hash/SHA-256",
		"Encryption/RSA1_5", "Encryption/AES-128-CBC", "Encryption/AES-256-GCM", "Encryption/frobnicate",
	} {
		a, ok := got["saml-algorithm/"+want]
		if !ok {
			t.Errorf("missing %s", want)
			continue
		}
		if a.Metadata["kind"] != "saml-algorithm" || a.Metadata["uri"] == "" {
			t.Errorf("%s metadata = %v", want, a.Metadata)
		}
	}
	if got["saml-algorithm/Signature/RSA-SHA1"].Metadata["element"] != "SignatureMethod" {
		t.Errorf("rsa-sha1 should come from SignatureMethod, got %s", got["saml-algorithm/Signature/RSA-SHA1"].Metadata["element"])
	}
}

func TestParseKeyDescriptorWithoutUseIsBoth(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := certB64(t, key, &key.PublicKey, x509.SHA256WithRSA)
	doc := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp">
  <SPSSODescriptor>
    <KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + c + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
    <KeyDescriptor><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + c + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
  </SPSSODescriptor>
</EntityDescriptor>`
	assets, err := Parse("sp.xml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	usages := map[model.Usage]int{}
	for _, a := range assets {
		if a.Metadata["kind"] == "certificate" {
			usages[a.Usage]++
		}
	}
	if usages[model.UsageSignature] != 1 || usages[model.UsageEncryption] != 1 {
		t.Errorf("a use-less KeyDescriptor is both signing and encryption, once each (same cert twice must dedupe): %v", usages)
	}
}

func TestParseFederationAggregate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	c := certB64(t, key, &key.PublicKey, x509.SHA256WithRSA)
	doc := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <EntityDescriptor entityID="https://a.example"><IDPSSODescriptor><KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + c + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor></IDPSSODescriptor></EntityDescriptor>
  <EntityDescriptor entityID="https://b.example"><SPSSODescriptor><KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + c + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor></SPSSODescriptor></EntityDescriptor>
</EntitiesDescriptor>`
	assets, err := Parse("fed.xml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	locs := map[string]bool{}
	for _, a := range assets {
		if a.Metadata["kind"] == "certificate" {
			locs[a.Location] = true
		}
	}
	if !locs["https://a.example cert#0"] || !locs["https://b.example cert#0"] {
		t.Errorf("each entity gets its own location, got %v", locs)
	}
}

func TestParseRejectsNonMetadata(t *testing.T) {
	for name, doc := range map[string]string{
		"html":      "<html><body>login</body></html>",
		"malformed": "<EntityDescriptor entityID='x'><IDPSSODescriptor></EntityDescriptor>",
	} {
		if _, err := Parse(name, []byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestParseSurfacesUnparseableCertificate(t *testing.T) {
	doc := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><IDPSSODescriptor><KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>bm90IGEgY2VydA==</X509Certificate></X509Data></KeyInfo></KeyDescriptor></IDPSSODescriptor></EntityDescriptor>`
	assets, err := Parse("x.xml", []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].Algorithm != "Unknown" || assets[0].Metadata["error"] == "" {
		t.Errorf("an unreadable certificate must surface as Unknown with the error, got %+v", assets)
	}
}

func TestScanFromURLAndFile(t *testing.T) {
	doc := metadata(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "samlmetadata") {
			t.Errorf("Accept header = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Write([]byte(doc))
	}))
	t.Cleanup(srv.Close)

	p := &Probe{Client: srv.Client()}
	fromURL, err := p.Scan(context.Background(), srv.URL+"/metadata")
	if err != nil {
		t.Fatalf("Scan(url): %v", err)
	}

	path := filepath.Join(t.TempDir(), "idp.xml")
	if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	fromFile, err := p.Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan(file): %v", err)
	}
	if len(fromURL) == 0 || len(fromURL) != len(fromFile) {
		t.Errorf("url and file scans of the same document differ: %d vs %d assets", len(fromURL), len(fromFile))
	}

	if _, err := p.Scan(context.Background(), filepath.Join(t.TempDir(), "missing.xml")); err == nil {
		t.Error("missing file must be an error")
	}
}
