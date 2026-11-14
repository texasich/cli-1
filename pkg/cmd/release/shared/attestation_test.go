package shared

import (
	"testing"

	"github.com/cli/cli/v2/internal/ghrepo"
	"github.com/cli/cli/v2/pkg/cmd/attestation/api"
	"github.com/cli/cli/v2/pkg/cmd/attestation/test/data"
	"github.com/cli/cli/v2/pkg/cmd/attestation/verification"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"
)

func TestFilterAttestations_NilDsseEnvelopeDoesNotPanic(t *testing.T) {
	validAtt := &api.Attestation{
		Bundle: data.GitHubReleaseBundle(t),
	}
	messageSigAtt := &api.Attestation{
		Bundle: &bundle.Bundle{
			Bundle: &protobundle.Bundle{
				MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
				Content:   &protobundle.Bundle_MessageSignature{},
			},
		},
	}
	nilBundleAtt := &api.Attestation{}

	attestations := []*api.Attestation{nil, nilBundleAtt, messageSigAtt, validAtt}

	filteredByTag, err := FilterAttestationsByTag(attestations, "v6")
	require.NoError(t, err)
	require.Len(t, filteredByTag, 1)
	require.Same(t, validAtt, filteredByTag[0])

	filteredByDigest, err := FilterAttestationsByFileDigest(
		attestations,
		"e15b593c6ab8d7725a3cc82226ef816cac6bf9c70eed383bd459295cc65f5ec3",
	)
	require.NoError(t, err)
	require.Len(t, filteredByDigest, 1)
	require.Same(t, validAtt, filteredByDigest[0])
}

func TestVerifyReleaseRepository(t *testing.T) {
	res := &verification.AttestationProcessingResult{
		Attestation: &api.Attestation{
			Bundle: data.GitHubReleaseBundle(t),
		},
	}

	t.Run("exact repository match succeeds", func(t *testing.T) {
		repo, err := ghrepo.FromFullName("bdehamer/delme")
		require.NoError(t, err)
		require.NoError(t, VerifyReleaseRepository(res, repo))
	})

	t.Run("case-insensitive repository match succeeds", func(t *testing.T) {
		repo, err := ghrepo.FromFullName("BDEHAMER/DELME")
		require.NoError(t, err)
		require.NoError(t, VerifyReleaseRepository(res, repo))
	})

	t.Run("mismatched repository fails", func(t *testing.T) {
		repo, err := ghrepo.FromFullName("other-owner/other-repo")
		require.NoError(t, err)
		err = VerifyReleaseRepository(res, repo)
		require.ErrorContains(t, err, `attestation repository "bdehamer/delme" does not match expected repository "other-owner/other-repo"`)
	})
}
