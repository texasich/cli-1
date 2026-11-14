package api

import (
	"errors"
	"fmt"

	v1 "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/encoding/protojson"
)

var ErrNoAttestationsFound = errors.New("no attestations found")

type Attestation struct {
	Bundle    *bundle.Bundle `json:"bundle"`
	BundleURL string         `json:"bundle_url"`
	Initiator string         `json:"initiator"`
}

type AttestationsResponse struct {
	Attestations []*Attestation `json:"attestations"`
}

type IntotoStatement struct {
	PredicateType string `json:"predicateType"`
}

func FilterAttestations(predicateType string, attestations []*Attestation) ([]*Attestation, error) {
	filteredAttestations := []*Attestation{}

	for _, each := range attestations {
		if each == nil || each.Bundle == nil {
			continue
		}
		dsseEnvelope := each.Bundle.GetDsseEnvelope()
		if dsseEnvelope != nil {
			if dsseEnvelope.PayloadType != "application/vnd.in-toto+json" {
				// Don't fail just because an entry isn't intoto
				continue
			}
			var intotoStatement v1.Statement
			if err := protojson.Unmarshal(dsseEnvelope.Payload, &intotoStatement); err != nil {
				// Don't fail just because a single entry can't be unmarshalled
				continue
			}
			if intotoStatement.PredicateType == predicateType {
				filteredAttestations = append(filteredAttestations, each)
			}
		}
	}

	if len(filteredAttestations) == 0 {
		return nil, fmt.Errorf("no attestations found with predicate type: %s", predicateType)
	}

	return filteredAttestations, nil
}
