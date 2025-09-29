package delegation

import (
	"testing"

	capassert "github.com/storacha/go-libstoracha/capabilities/assert"
	capblob "github.com/storacha/go-libstoracha/capabilities/blob"
	capreplica "github.com/storacha/go-libstoracha/capabilities/blob/replica"
	capclaim "github.com/storacha/go-libstoracha/capabilities/claim"

	"github.com/storacha/go-ucanto/core/delegation"
	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"
	"github.com/storacha/go-ucanto/ucan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDelegationRoundTrip(t *testing.T) {
	// Generate signers for testing
	uploadService, err := ed25519.Generate()
	require.NoError(t, err)

	indexerService, err := ed25519.Generate()
	require.NoError(t, err)

	storageNode, err := ed25519.Generate()
	require.NoError(t, err)

	testCases := []struct {
		name         string
		issuer       ucan.Signer
		audience     ucan.Principal
		capabilities []string
		expectedCaps []string
	}{
		{
			name:         "IndexerToUpload",
			issuer:       indexerService,
			audience:     uploadService,
			capabilities: []string{capassert.EqualsAbility, capassert.IndexAbility},
			expectedCaps: []string{
				capassert.EqualsAbility,
				capassert.IndexAbility,
			},
		},
		{
			name:         "StorageToUpload",
			issuer:       storageNode,
			audience:     uploadService,
			capabilities: []string{capblob.AllocateAbility, capblob.AcceptAbility, capreplica.AllocateAbility},
			expectedCaps: []string{
				capblob.AllocateAbility,
				capblob.AcceptAbility,
				capreplica.AllocateAbility,
			},
		},
		{
			name:         "IndexerToStorage",
			issuer:       indexerService,
			audience:     storageNode,
			capabilities: []string{capclaim.CacheAbility},
			expectedCaps: []string{
				capclaim.CacheAbility,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate delegation
			deleg, err := MakeDelegation(tc.issuer, tc.audience, tc.capabilities)
			require.NoError(t, err)

			// Format as multibase string
			dlgStr, err := delegation.Format(deleg)
			require.NoError(t, err)

			// Parse the delegation
			info, err := ParseDelegationContent(dlgStr)
			require.NoError(t, err)

			// Verify issuer and audience DIDs
			assert.NotEmpty(t, info.Issuer)
			assert.NotEmpty(t, info.Audience)

			// Verify capabilities count
			assert.Equal(t, len(tc.expectedCaps), len(info.Capabilities))

			// Verify the specific capability types
			capabilityTypes := make([]string, len(info.Capabilities))
			for i, cap := range info.Capabilities {
				capabilityTypes[i] = cap.Can
				assert.NotEmpty(t, cap.Can)
				assert.NotEmpty(t, cap.With)
			}

			// Verify each expected capability is present
			for _, expectedCap := range tc.expectedCaps {
				assert.Contains(t, capabilityTypes, expectedCap)
			}

			// Verify signature exists
			assert.NotEmpty(t, info.Signature)
		})
	}
}
