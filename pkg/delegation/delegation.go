package delegation

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-multihash"
	"github.com/storacha/go-libstoracha/capabilities/assert"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/blob/replica"
	"github.com/storacha/go-libstoracha/capabilities/claim"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/principal"
	"github.com/storacha/go-ucanto/ucan"
)

// DelegateIndexingToUpload creates a delegation from indexing service to upload service
func DelegateIndexingToUpload(indexer, upload principal.Signer) (delegation.Delegation, error) {
	return mkDelegation(indexer, upload, assert.EqualsAbility, assert.IndexAbility)
}

// DelegateStorageToUpload creates a delegation from storage provider to upload service
func DelegateStorageToUpload(storage, upload principal.Signer) (delegation.Delegation, error) {
	return mkDelegation(storage, upload, blob.AllocateAbility, blob.AcceptAbility, replica.AllocateAbility)
}

// DelegateIndexingToStorage creates a delegation from indexing service to storage provider
func DelegateIndexingToStorage(indexer ucan.Signer, storage ucan.Principal) (delegation.Delegation, error) {
	return mkDelegation(indexer, storage, claim.CacheAbility)
}

func mkDelegation(issuer ucan.Signer, audience ucan.Principal, capabilities ...string) (delegation.Delegation, error) {
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
		delegation.WithNoExpiration(),
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

// CapabilityInfo represents a capability in a delegation
type CapabilityInfo struct {
	With string `json:"with"`
	Can  string `json:"can"`
}

// DelegationInfo represents the structured information about a delegation
type DelegationInfo struct {
	Issuer       string                   `json:"issuer"`
	Audience     string                   `json:"audience"`
	Version      string                   `json:"version"`
	Expiration   *int                     `json:"expiration,omitempty"` // Can be nil or an int
	NotBefore    int                      `json:"notBefore"`
	Nonce        string                   `json:"nonce,omitempty"`
	Proofs       interface{}              `json:"proofs,omitempty"` // Complex type from ucan library
	Signature    []byte                   `json:"signature"`
	Capabilities []CapabilityInfo         `json:"capabilities"`
	Facts        []map[string]interface{} `json:"facts,omitempty"`
}

// ParseDelegationContent parses delegation content from a string and returns information about it
func ParseDelegationContent(content string) (*DelegationInfo, error) {
	// Trim any whitespace
	content = strings.TrimSpace(content)

	// Parse the delegation using go-ucanto library
	deleg, err := delegation.Parse(content)
	if err != nil {
		// If parsing fails, try to decode it from base64 first
		decoded, err := base64.StdEncoding.DecodeString(content)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 content: %w", err)
		}

		deleg, err = delegation.Parse(string(decoded))
		if err != nil {
			return nil, fmt.Errorf("failed to import delegation from decoded content: %w", err)
		}
	}

	// Build result struct with detail
	result := &DelegationInfo{
		Issuer:     deleg.Issuer().DID().String(),
		Audience:   deleg.Audience().DID().String(),
		Version:    deleg.Version(),
		Expiration: deleg.Expiration(),
		NotBefore:  deleg.NotBefore(),
		Nonce:      deleg.Nonce(),
		Proofs:     deleg.Proofs(),
		Signature:  deleg.Signature().Bytes(),
	}

	// Extract capabilities
	for _, c := range deleg.Capabilities() {
		capInfo := CapabilityInfo{
			With: c.With(),
			Can:  c.Can(),
		}
		result.Capabilities = append(result.Capabilities, capInfo)
	}

	// Extract facts
	for _, f := range deleg.Facts() {
		result.Facts = append(result.Facts, f)
	}

	return result, nil
}

// ParseDelegation reads a delegation from a file and returns information about it
func ParseDelegation(filePath string) (*DelegationInfo, error) {
	// Read the file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read delegation file: %w", err)
	}

	return ParseDelegationContent(string(data))
}

// ParseDelegationFromFile is a helper function that reads a single delegation file
// and returns detailed information about it
func ParseDelegationFromFile(filePath string) (*DelegationInfo, error) {
	return ParseDelegation(filePath)
}
