package delegation

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multicodec"
	"github.com/multiformats/go-multihash"
	"github.com/storacha/go-ucanto/core/dag/blockstore"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/ucan"
)

func MakeDelegation(issuer ucan.Signer, audience ucan.Principal, capabilities []string, with ucan.Resource, opts ...delegation.Option) (delegation.Delegation, error) {
	uc := make([]ucan.Capability[ucan.NoCaveats], len(capabilities))
	for i, capability := range capabilities {
		uc[i] = ucan.NewCapability(
			capability,
			with,
			ucan.NoCaveats{},
		)
	}

	return delegation.Delegate(
		issuer,
		audience,
		uc,
		opts...,
	)
}

// FormatDelegation takes a delegation archive from a read and returns a multibase-base64-encoded CIDv1 with
// embedded CAR data.
func FormatDelegation(d io.Reader) (string, error) {
	db, err := io.ReadAll(d)
	if err != nil {
		return "", fmt.Errorf("failed to read delegation: %w", err)
	}

	return FormatDelegationBytes(db)
}

// FormatDelegationBytes takes a delegation archive in byte form and returns a multibase-base64-encoded CIDv1 with
// embedded CAR data.
func FormatDelegationBytes(archive []byte) (string, error) {
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
	Issuer           string                   `json:"issuer"`
	Audience         string                   `json:"audience"`
	Version          string                   `json:"version"`
	Expiration       *int                     `json:"expiration,omitempty"` // Can be nil or an int
	NotBefore        int                      `json:"notBefore"`
	Nonce            string                   `json:"nonce,omitempty"`
	Proofs           interface{}              `json:"proofs,omitempty"`           // Complex type from ucan library
	ProofDelegations []*DelegationInfo        `json:"proofDelegations,omitempty"` // Parsed delegations from proofs
	Signature        []byte                   `json:"signature"`
	Capabilities     []CapabilityInfo         `json:"capabilities"`
	Facts            []map[string]interface{} `json:"facts,omitempty"`
}

// parseDelegationToDelegationInfo converts a ucanto delegation.Delegation to DelegationInfo
func parseDelegationToDelegationInfo(deleg delegation.Delegation) *DelegationInfo {
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

	// Process proofs recursively
	if len(deleg.Proofs()) > 0 {
		br, err := blockstore.NewBlockReader(blockstore.WithBlocksIterator(deleg.Blocks()))
		if err == nil {
			proofs := delegation.NewProofsView(deleg.Proofs(), br)
			for _, proof := range proofs {
				pd, ok := proof.Delegation()
				if !ok {
					continue
				}
				// Recursively parse the delegation from the proof
				proofDelegInfo := parseDelegationToDelegationInfo(pd)
				result.ProofDelegations = append(result.ProofDelegations, proofDelegInfo)
			}
		}
	}

	return result
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

	// Use the helper function to parse delegation recursively
	result := parseDelegationToDelegationInfo(deleg)

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
