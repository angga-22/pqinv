package report

import (
	"fmt"
	"io"
	"strconv"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/angga-22/pqinv/internal/model"
)

// CBOM writes a CycloneDX 1.6 Cryptography Bill of Materials: one
// cryptographic-asset component per verdict, with pqinv's classification
// carried in namespaced properties. No serial number and no timestamp,
// for the same determinism reason as the JSON renderer.
//
// v1 maps every asset as assetType "algorithm"; a finer mapping
// (certificate → certificateProperties, JWK → relatedCryptoMaterial) is
// a noted future refinement.
func CBOM(w io.Writer, version string, reports []TargetReport) error {
	bom := cdx.NewBOM()
	// Stamp the document as 1.6 directly and use Encode (no conversion)
	// instead of EncodeVersion: cyclonedx-go v0.12.0's spec-version
	// converter has a bug — supportsComponentType() lacks a case for
	// "cryptographic-asset", so conversion silently rewrites every
	// crypto component to type "application". Everything pqinv emits is
	// already valid 1.6, so skipping conversion is safe.
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.JSONSchema = "http://cyclonedx.org/schema/bom-1.6.schema.json"
	bom.Metadata = &cdx.Metadata{
		Tools: &cdx.ToolsChoice{
			Components: &[]cdx.Component{{
				Type:    cdx.ComponentTypeApplication,
				Name:    "pqinv",
				Version: version,
			}},
		},
	}

	var components []cdx.Component
	for _, rep := range reports {
		if rep.Error != "" {
			continue // unreachable targets have no assets to declare
		}
		for i, v := range rep.Verdicts {
			components = append(components, cryptoComponent(rep, i, v))
		}
	}
	bom.Components = &components

	enc := cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON)
	enc.SetPretty(true)
	return enc.Encode(bom)
}

func cryptoComponent(rep TargetReport, idx int, v model.Verdict) cdx.Component {
	a := v.Asset
	props := []cdx.Property{
		{Name: "pqinv:source", Value: a.Source},
		{Name: "pqinv:location", Value: a.Location},
		{Name: "pqinv:usage", Value: string(a.Usage)},
		{Name: "pqinv:class", Value: string(v.Class)},
		{Name: "pqinv:urgency", Value: string(v.Urgency)},
	}
	if v.Migration != "" {
		props = append(props, cdx.Property{Name: "pqinv:migration", Value: v.Migration})
	}
	if a.KeyBits > 0 {
		props = append(props, cdx.Property{Name: "pqinv:key_bits", Value: strconv.Itoa(a.KeyBits)})
	}

	return cdx.Component{
		// Index keeps refs unique when one target holds the same
		// algorithm at several locations (three chain certs, say).
		BOMRef: fmt.Sprintf("pqinv:%s:%s:%d", a.Source, rep.Target, idx),
		Type:   cdx.ComponentTypeCryptographicAsset,
		Name:   a.Algorithm,
		CryptoProperties: &cdx.CryptoProperties{
			AssetType: cdx.CryptoAssetTypeAlgorithm,
			AlgorithmProperties: &cdx.CryptoAlgorithmProperties{
				Primitive: primitiveFor(a.Usage),
			},
		},
		Properties: &props,
	}
}

func primitiveFor(u model.Usage) cdx.CryptoPrimitive {
	switch u {
	case model.UsageKeyExchange:
		return cdx.CryptoPrimitiveKeyAgree
	case model.UsageSignature:
		return cdx.CryptoPrimitiveSignature
	case model.UsageHash:
		return cdx.CryptoPrimitiveHash
	case model.UsageEncryption:
		return cdx.CryptoPrimitiveBlockCipher
	default:
		return cdx.CryptoPrimitiveOther
	}
}
