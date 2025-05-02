package delegation

import (
	"io"
	"testing"

	capassert "github.com/storacha/go-libstoracha/capabilities/assert"
	capblob "github.com/storacha/go-libstoracha/capabilities/blob"
	capclaim "github.com/storacha/go-libstoracha/capabilities/claim"

	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"
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
		delegFn      func() ([]byte, error)
		expectedCaps []string
	}{
		{
			name: "IndexerToUpload",
			delegFn: func() ([]byte, error) {
				deleg, err := DelegateIndexingToUpload(indexerService, uploadService)
				if err != nil {
					return nil, err
				}

				bytes, err := io.ReadAll(deleg.Archive())
				if err != nil {
					return nil, err
				}

				return bytes, nil
			},
			expectedCaps: []string{
				capassert.EqualsAbility,
				capassert.IndexAbility,
			},
		},
		{
			name: "StorageToUpload",
			delegFn: func() ([]byte, error) {
				deleg, err := DelegateStorageToUpload(storageNode, uploadService)
				if err != nil {
					return nil, err
				}

				bytes, err := io.ReadAll(deleg.Archive())
				if err != nil {
					return nil, err
				}

				return bytes, nil
			},
			expectedCaps: []string{
				capblob.AllocateAbility,
				capblob.AcceptAbility,
			},
		},
		{
			name: "IndexerToStorage",
			delegFn: func() ([]byte, error) {
				deleg, err := DelegateIndexingToStorage(indexerService, storageNode)
				if err != nil {
					return nil, err
				}

				bytes, err := io.ReadAll(deleg.Archive())
				if err != nil {
					return nil, err
				}

				return bytes, nil
			},
			expectedCaps: []string{
				capclaim.CacheAbility,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate delegation
			archiveBytes, err := tc.delegFn()
			require.NoError(t, err)

			// Format as base64
			b64, err := FormatDelegation(archiveBytes)
			require.NoError(t, err)
			assert.NotEmpty(t, b64)

			// Parse the delegation
			info, err := ParseDelegationContent(b64)
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
