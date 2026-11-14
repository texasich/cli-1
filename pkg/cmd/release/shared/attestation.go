package shared

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/cli/cli/v2/internal/ghrepo"
	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/artifact"
	att_io "github.com/cli/cli/v2/pkg/cmd/attestation/io"
	"github.com/cli/cli/v2/pkg/cmd/attestation/test/data"
	"github.com/cli/cli/v2/pkg/cmd/attestation/verification"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"

	v1 "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

type Verifier interface {
	// VerifyAttestation verifies the attestation for a given artifact
	VerifyAttestation(art *artifact.DigestedArtifact, att *api.Attestation) (*verification.AttestationProcessingResult, error)
}

type AttestationVerifier struct {
	AttClient          api.Client
	ExternalHttpClient *http.Client
	IO                 *iostreams.IOStreams
	TrustedRoot        string
	BaseRepo           ghrepo.Interface
}

func (v *AttestationVerifier) VerifyAttestation(art *artifact.DigestedArtifact, att *api.Attestation) (*verification.AttestationProcessingResult, error) {
	td, err := v.AttClient.GetTrustDomain()
	if err != nil {
		return nil, err
	}

	verifier, err := verification.NewLiveSigstoreVerifier(verification.SigstoreConfig{
		ExternalHttpClient: v.ExternalHttpClient,
		Logger:             att_io.NewHandler(v.IO),
		NoPublicGood:       true,
		TrustDomain:        td,
		TrustedRoot:        v.TrustedRoot,
	})
	if err != nil {
		return nil, err
	}

	policy := buildVerificationPolicy(*art, td)
	sigstoreVerified, err := verifier.Verify([]*api.Attestation{att}, policy)
	if err != nil {
		return nil, err
	}

	if err := VerifyReleaseRepository(sigstoreVerified[0], v.BaseRepo); err != nil {
		return nil, err
	}

	return sigstoreVerified[0], nil
}

func dssePayload(att *api.Attestation) ([]byte, bool) {
	if att == nil || att.Bundle == nil || att.Bundle.Bundle == nil {
		return nil, false
	}
	dsseEnvelope := att.Bundle.Bundle.GetDsseEnvelope()
	if dsseEnvelope == nil {
		return nil, false
	}
	return dsseEnvelope.Payload, true
}

// VerifyReleaseRepository checks that the in-toto statement's predicate.repository
// field matches baseRepo case-insensitively.
func VerifyReleaseRepository(res *verification.AttestationProcessingResult, baseRepo ghrepo.Interface) error {
	if baseRepo == nil {
		return nil
	}
	if res == nil {
		return errors.New("nil attestation verification result")
	}

	var statementData *v1.Statement
	if res.VerificationResult != nil && res.VerificationResult.Statement != nil {
		statementData = res.VerificationResult.Statement
	} else {
		payload, ok := dssePayload(res.Attestation)
		if !ok {
			return errors.New("attestation bundle does not contain a DSSE envelope")
		}
		var parsed v1.Statement
		if err := protojson.Unmarshal(payload, &parsed); err != nil {
			return fmt.Errorf("failed to unmarshal statement: %w", err)
		}
		statementData = &parsed
	}

	repoValue := statementData.GetPredicate().GetFields()["repository"].GetStringValue()
	expectedRepo := ghrepo.FullName(baseRepo)
	if !strings.EqualFold(repoValue, expectedRepo) {
		return fmt.Errorf("attestation repository %q does not match expected repository %q", repoValue, expectedRepo)
	}
	return nil
}

func FilterAttestationsByTag(attestations []*api.Attestation, tagName string) ([]*api.Attestation, error) {
	var filtered []*api.Attestation
	for _, att := range attestations {
		statement, ok := dssePayload(att)
		if !ok {
			continue
		}
		var statementData v1.Statement
		err := protojson.Unmarshal(statement, &statementData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
		}
		tagValue := statementData.GetPredicate().GetFields()["tag"].GetStringValue()

		if tagValue == tagName {
			filtered = append(filtered, att)
		}
	}
	return filtered, nil
}

func FilterAttestationsByFileDigest(attestations []*api.Attestation, fileDigest string) ([]*api.Attestation, error) {
	var filtered []*api.Attestation
	for _, att := range attestations {
		statement, ok := dssePayload(att)
		if !ok {
			continue
		}
		var statementData v1.Statement
		err := protojson.Unmarshal(statement, &statementData)

		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal statement: %w", err)
		}
		subjects := statementData.Subject
		for _, subject := range subjects {
			digestMap := subject.GetDigest()
			alg := "sha256"

			digest := digestMap[alg]
			if digest == fileDigest {
				filtered = append(filtered, att)
			}
		}

	}
	return filtered, nil
}

// buildVerificationPolicy constructs a verification policy for GitHub releases
func buildVerificationPolicy(a artifact.DigestedArtifact, trustDomain string) verify.PolicyBuilder {
	// If no trust domain is specified, default to "dotcom"
	if trustDomain == "" {
		trustDomain = "dotcom"
	}
	// SAN must match the GitHub releases domain. No issuer extension (match anything)
	sanMatcher, _ := verify.NewSANMatcher("", fmt.Sprintf("^https://%s\\.releases\\.github\\.com$", trustDomain))
	issuerMatcher, _ := verify.NewIssuerMatcher("", ".*")
	certId, _ := verify.NewCertificateIdentity(sanMatcher, issuerMatcher, certificate.Extensions{})

	artifactDigestPolicyOption, _ := verification.BuildDigestPolicyOption(a)
	return verify.NewPolicy(artifactDigestPolicyOption, verify.WithCertificateIdentity(certId))
}

type MockVerifier struct {
	mockResult *verification.AttestationProcessingResult
}

func NewMockVerifier(mockResult *verification.AttestationProcessingResult) *MockVerifier {
	return &MockVerifier{mockResult: mockResult}
}

func (v *MockVerifier) VerifyAttestation(art *artifact.DigestedArtifact, att *api.Attestation) (*verification.AttestationProcessingResult, error) {
	return &verification.AttestationProcessingResult{
		Attestation: &api.Attestation{
			Bundle:    data.GitHubReleaseBundle(nil),
			BundleURL: "https://example.com",
		},
		VerificationResult: nil,
	}, nil
}
