package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/storacha/go-libstoracha/capabilities/assert"
	"github.com/storacha/go-libstoracha/capabilities/blob"
	"github.com/storacha/go-libstoracha/capabilities/claim"
	"github.com/storacha/go-libstoracha/capabilities/http"
	"github.com/storacha/go-libstoracha/capabilities/pdp"
	spaceblob "github.com/storacha/go-libstoracha/capabilities/space/blob"
	"github.com/storacha/go-libstoracha/capabilities/ucan"
	"github.com/storacha/go-ucanto/core/delegation"
	"github.com/storacha/go-ucanto/did"
	"github.com/storacha/go-ucanto/principal"
	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"
	"github.com/storacha/go-ucanto/principal/signer"

	mkd "github.com/storacha/go-mkdelegation/pkg/delegation"
)

var (
	// Gen command flags
	issuerPrivateKeyFile     string
	issuerPrivateKey         string
	issuerDidWebKey          string
	audienceDidKey           string
	capabilities             []string
	skipCapabilityValidation bool
	expiration               int64
)

// genCmd represents the gen command
var genCmd = &cobra.Command{
	Use:          "gen",
	Aliases:      []string{"g"},
	Short:        "Generate a UCAN delegation",
	SilenceUsage: true,
	RunE:         mkDelegation,
}

func init() {
	rootCmd.AddCommand(genCmd)

	genCmd.Flags().StringVarP(&issuerPrivateKeyFile, "issuer-private-key-file", "f", "", "Path to PEM encoded Ed25519 private key of delegation issuer")
	genCmd.Flags().StringVarP(&issuerPrivateKey, "issuer-private-key", "i", "", "Multibase encoded Ed25519 private key of delegation issuer")
	genCmd.MarkFlagsMutuallyExclusive("issuer-private-key-file", "issuer-private-key")
	genCmd.MarkFlagsOneRequired("issuer-private-key-file", "issuer-private-key")

	genCmd.Flags().StringVarP(&issuerDidWebKey, "issuer-did-web", "w", "", "Optional did:web: of issuer, when provided warps did:key: of delegation issuer")

	genCmd.Flags().StringVarP(&audienceDidKey, "audience-did-key", "a", "", "did:key of delegation audience")
	Must(genCmd.MarkFlagRequired("audience-did-key"))

	genCmd.Flags().StringArrayVarP(&capabilities, "capabilities", "c", []string{}, "list of capabilities issuer will authorize to audience")
	Must(genCmd.MarkFlagRequired("capabilities"))
	genCmd.Flags().BoolVarP(&skipCapabilityValidation, "skip-capability-validation", "s", false, "when set skips validation of capabilities against known set of capabilities")
	genCmd.Flags().Int64VarP(&expiration, "expiration", "e", 0, "expiration time in UTC seconds since Unix\n// epoch")
}

func mkDelegation(cmd *cobra.Command, args []string) error {
	var issuer principal.Signer
	if issuerPrivateKeyFile != "" {
		var err error
		issuer, err = parseIssuerKey(issuerPrivateKeyFile)
		if err != nil {
			return fmt.Errorf("parsing issuer private key from file %s: %w", issuerPrivateKeyFile, err)
		}
	} else {
		var err error
		issuer, err = ed25519.Parse(issuerPrivateKey)
		if err != nil {
			return fmt.Errorf("parsing issuer private key: %w", err)
		}
	}

	if issuerDidWebKey != "" {
		if !strings.HasPrefix(issuerDidWebKey, "did:web:") {
			return fmt.Errorf("issuer did:web: must start with 'did:web:' prefix")
		}
		issuerDidWeb, err := did.Parse(issuerDidWebKey)
		if err != nil {
			return fmt.Errorf("parsing issuer did web key (%s): %w", issuerDidWebKey, err)
		}
		issuer, err = signer.Wrap(issuer, issuerDidWeb)
		if err != nil {
			return fmt.Errorf("wrapping issuer with did web key (%s): %w", issuerDidWebKey, err)
		}
	}

	audience, err := did.Parse(audienceDidKey)
	if err != nil {
		return fmt.Errorf("parsing audience did key: %w", err)
	}

	if !skipCapabilityValidation {
		if err := validateCapability(capabilities); err != nil {
			// TODO consider returning the list of known capabilities in the event of a failure for more discoverable UX
			// alternatively, there could be a `list capabilities` command that allows you to list the set of known
			// capabilities validation will be performed against
			return fmt.Errorf("capabilities validation failed (pass --skip-capability-validation) to skip capabilities validation: %w", err)
		}
	}

	var opts []delegation.Option
	if expiration > 0 {
		if time.Now().Unix() > expiration {
			return fmt.Errorf("provided expiration time %d is in the past", expiration)
		}
		opts = append(opts, delegation.WithExpiration(int(expiration)))
	} else {
		opts = append(opts, delegation.WithNoExpiration())
	}

	d, err := mkd.MakeDelegation(issuer, audience, capabilities, opts...)
	if err != nil {
		return fmt.Errorf("making delegation: %w", err)
	}

	out, err := mkd.FormatDelegation(d.Archive())
	if err != nil {
		return fmt.Errorf("formatting delegation: %w", err)
	}
	fmt.Println(out)
	return nil
}

// KnownCapabilities is the set of known storacha service capabilities for a delegation
// TODO: define a set in go-libstoracha that can be updated independently of this
var KnownCapabilities = map[string]bool{
	assert.EqualsAbility:       true,
	assert.RelationAbility:     true,
	assert.PartitionAbility:    true,
	assert.IndexAbility:        true,
	assert.InclusionAbility:    true,
	assert.LocationAbility:     true,
	blob.AcceptAbility:         true,
	blob.AllocateAbility:       true,
	claim.CacheAbility:         true,
	http.PutAbility:            true,
	pdp.AcceptAbility:          true,
	pdp.InfoAbility:            true,
	spaceblob.AddAbility:       true,
	spaceblob.GetAbility:       true,
	spaceblob.ListAbility:      true,
	spaceblob.RemoveAbility:    true,
	spaceblob.ReplicateAbility: true,
	ucan.ConcludeAbility:       true,
}

func validateCapability(capabilities []string) error {
	var errs error
	for _, capability := range capabilities {
		if !KnownCapabilities[capability] {
			errs = multierror.Append(errs, fmt.Errorf("unknown capability: %s", capability))
		}
	}
	return errs
}

// parseIssuerKey attempts to read and parse the private key from the
// provided path.
func parseIssuerKey(path string) (principal.Signer, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	return parsePrivateKeyPEM(f)
}
