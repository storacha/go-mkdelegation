package delegation

import (
	"fmt"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-multihash"
	"github.com/storacha/go-libstoracha/capabilities/assert"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/claim"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/ucan"
)

// DelegateIndexingToUpload creates a delegation from indexing service to upload service
func DelegateIndexingToUpload(indexer, upload principal.Signer) (delegation.Delegation, error) {
	return mkDelegation(indexer, upload, assert.IndexAbility, assert.EqualsAbility)
}

// DelegateStorageToUpload creates a delegation from storage provider to upload service
func DelegateStorageToUpload(storage, upload principal.Signer) (delegation.Delegation, error) {
	return mkDelegation(storage, upload, blob.AllocateAbility, blob.AcceptAbility)
}

// DelegateIndexingToStorage creates a delegation from indexing service to storage provider
func DelegateIndexingToStorage(indexer, storage principal.Signer) (delegation.Delegation, error) {
	return mkDelegation(indexer, storage, claim.CacheAbility)
}

func mkDelegation(issuer, audience principal.Signer, capabilities ...string) (delegation.Delegation, error) {
	uc := make([]ucan.Capability[ucan.NoCaveats], len(capabilities))
	for i, capability := range capabilities {
		uc[i] = ucan.NewCapability(
			capability,
			issuer.DID().String(),
			ucan.NoCaveats{},
		)
	}

	return delegation.Delegate(
		issuer,
		audience,
		uc,
	)
}

// FormatDelegation takes a delegation archive in byte form and returns a base64-encoded link
func FormatDelegation(archive []byte) (string, error) {
	// Create identity digest of the archive
	// The identity hash function (0x00) simply returns the input data as the hash
	mh, err := multihash.Sum(archive, multihash.IDENTITY, -1)
	if err != nil {
		return "", fmt.Errorf("failed to create identity hash: %w", err)
	}

	// Create a CID (Content IDentifier) with codec 0x0202 (CAR format)
	// The 0x0202 codec is defined in the multicodec table for Content Addressable aRchives (CAR)
	link := cid.NewCidV1(uint64(multicodec.Car), mh)

	// Convert the CID to base64 encoding
	str, err := link.StringOfBase(multibase.Base64)
	if err != nil {
		return "", fmt.Errorf("failed to encode CID to base64: %w", err)
	}

	return str, nil
}
