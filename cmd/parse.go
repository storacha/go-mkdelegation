package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"

	"github.com/storacha/go-mkdelegation/pkg/delegation"
)

var (
	// Parse command flags
	parseJsonOutput bool
)

// parseCmd represents the parse command
var parseCmd = &cobra.Command{
	Use:     "parse [DELEGATION_FILE]",
	Aliases: []string{"p"},
	Short:   "Parse and display information about a UCAN delegation from a file or stdin",
	Long: `Parses a UCAN delegation from a file or stdin if no file is provided.
   Examples:
     - Parse from file: mkdelegation parse delegation.b64
     - Parse from stdin: cat delegation.b64 | mkdelegation parse
     - Parse directly: echo 'base64content' | mkdelegation parse`,
	Args:         cobra.MaximumNArgs(1),
	SilenceUsage: true,
	RunE:         parseDelegation,
}

func init() {
	rootCmd.AddCommand(parseCmd)

	parseCmd.Flags().BoolVarP(&parseJsonOutput, "json", "j", false, "Output in JSON format")
}

// parseDelegation reads a delegation from a file or stdin and displays its information
func parseDelegation(cmd *cobra.Command, args []string) error {
	var info *delegation.DelegationInfo
	var err error

	// Check if a file path is provided
	if len(args) >= 1 {
		filePath := args[0]

		// Check if file exists
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return fmt.Errorf("file does not exist: %s", filePath)
		}

		// Parse the delegation from file
		info, err = delegation.ParseDelegationFromFile(filePath)
		if err != nil {
			return fmt.Errorf("failed to parse delegation: %w", err)
		}
	} else {
		// No file provided, read from stdin
		stdinData, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("failed to read from stdin: %w", err)
		}

		if len(stdinData) == 0 {
			return fmt.Errorf("no input provided via stdin and no file specified")
		}

		// Parse the delegation from stdin content
		info, err = delegation.ParseDelegationContent(string(stdinData))
		if err != nil {
			return fmt.Errorf("failed to parse delegation from stdin: %w", err)
		}
	}

	// Output as JSON if requested
	if parseJsonOutput {
		jsonOutput, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal delegation info to JSON: %w", err)
		}
		cmd.Println(string(jsonOutput))
		return nil
	}

	// Use the formatDelegationAsTable function to format the delegation
	cmd.Println("Delegation Information:")
	cmd.Println(formatDelegationAsTable(info, 0))

	return nil
}

// formatDelegationAsTable formats a single delegation as a complete table
func formatDelegationAsTable(info *delegation.DelegationInfo, depth int) string {
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Property", "Value"})
	table.SetAutoWrapText(true)
	table.SetAutoMergeCells(false)
	table.SetRowLine(true)
	table.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT})
	table.SetColWidth(60 - (depth * 2)) // Adjust width based on nesting

	// Add delegation metadata rows
	table.Append([]string{"Issuer", info.Issuer})
	table.Append([]string{"Audience", info.Audience})
	table.Append([]string{"Version", info.Version})
	table.Append([]string{"Nonce", fmt.Sprintf("%v", info.Nonce)})
	if depth == 0 { // Only show raw proofs at top level
		table.Append([]string{"Proofs", fmt.Sprintf("%v", info.Proofs)})
	}
	table.Append([]string{"Signature (b64)", base64.StdEncoding.EncodeToString(info.Signature)})
	if info.Expiration != nil {
		table.Append([]string{"Expiration", strconv.Itoa(*info.Expiration) + fmt.Sprintf(" (%s)", time.Unix(int64(*info.Expiration), 0).UTC().Format(time.RFC822))})
	}
	table.Append([]string{"Not Before", strconv.Itoa(info.NotBefore)})

	// Create capabilities table as a subtable
	var capTable string
	if len(info.Capabilities) > 0 {
		capTableString := &strings.Builder{}
		capTableWriter := tablewriter.NewWriter(capTableString)
		capTableWriter.SetHeader([]string{"#", "Can", "With"})
		capTableWriter.SetAutoWrapText(true)
		capTableWriter.SetAutoMergeCells(false)
		capTableWriter.SetRowLine(true)
		capTableWriter.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT})
		capTableWriter.SetColWidth(50 - (depth * 2))

		for i, capability := range info.Capabilities {
			capTableWriter.Append([]string{fmt.Sprintf("%d", i+1), capability.Can, capability.With})
		}

		capTableWriter.Render()
		capTable = capTableString.String()
	} else {
		capTable = "None"
	}
	table.Append([]string{"Capabilities", capTable})

	// Create facts table as a subtable
	var factTable string
	if len(info.Facts) > 0 {
		factTableString := &strings.Builder{}
		factTableWriter := tablewriter.NewWriter(factTableString)
		factTableWriter.SetHeader([]string{"#", "Fact"})
		factTableWriter.SetAutoWrapText(true)
		factTableWriter.SetAutoMergeCells(false)
		factTableWriter.SetRowLine(true)
		factTableWriter.SetColumnAlignment([]int{tablewriter.ALIGN_CENTER, tablewriter.ALIGN_LEFT})
		factTableWriter.SetColWidth(50 - (depth * 2))

		for i, f := range info.Facts {
			factTableWriter.Append([]string{fmt.Sprintf("%d", i+1), fmt.Sprintf("%v", f)})
		}

		factTableWriter.Render()
		factTable = factTableString.String()
	} else {
		factTable = "None"
	}
	table.Append([]string{"Facts", factTable})

	// Create proof delegations table recursively
	if len(info.ProofDelegations) > 0 {
		proofDelegsTable := formatProofDelegations(info.ProofDelegations, depth+1)
		table.Append([]string{"Proof Delegations", proofDelegsTable})
	}

	table.Render()
	return tableString.String()
}

// formatProofDelegations recursively formats proof delegations as nested tables
func formatProofDelegations(proofDelegations []*delegation.DelegationInfo, depth int) string {
	if len(proofDelegations) == 0 {
		return "None"
	}

	var result strings.Builder

	for i, pd := range proofDelegations {
		if i > 0 {
			result.WriteString("\n")
		}
		result.WriteString(fmt.Sprintf("\n=== Proof Delegation %d ===\n", i+1))
		// Recursively format each proof delegation as a complete table
		result.WriteString(formatDelegationAsTable(pd, depth))
	}

	return result.String()
}
