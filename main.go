package main

import (
	crypto_ed25519 "crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"

	"github.com/storacha/go-ucanto/principal"
	ed25519 "github.com/storacha/go-ucanto/principal/ed25519/signer"

	"github.com/storacha/go-mkdelegation/pkg/delegation"
)

// Output structs for JSON format
type ServiceInfo struct {
	Name      string `json:"name"`
	DID       string `json:"did"`
	SecretKey string `json:"secretKey"`
}

type DelegationInfo struct {
	Path string `json:"path"`
	UCAN string `json:"ucan"`
}

type OutputData struct {
	Services    []ServiceInfo    `json:"services"`
	Delegations []DelegationInfo `json:"delegations"`
}

func main() {
	app := &cli.App{
		Name:  "mkdelegation",
		Usage: "Manage UCAN delegations for various service interactions",
		Commands: []*cli.Command{
			{
				Name:    "gen",
				Aliases: []string{"g"},
				Usage:   "Generate UCAN delegations for various service interactions",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:      "upload-service-private-key",
						Aliases:   []string{"u"},
						Usage:     "Path to PEM encoded Ed25519 private key of the Upload Service",
						TakesFile: true,
					},
					&cli.StringFlag{
						Name:      "indexing-service-private-key",
						Aliases:   []string{"i"},
						Usage:     "Path to PEM encoded Ed25519 private key of the Indexing Service",
						TakesFile: true,
					},
					&cli.StringFlag{
						Name:      "storage-node-private-key",
						Aliases:   []string{"n"},
						Usage:     "Path to PEM encoded Ed25519 private key of the Storage Node",
						TakesFile: true,
					},
					&cli.BoolFlag{
						Name:    "json",
						Aliases: []string{"j"},
						Usage:   "Output in JSON format to a file",
					},
					&cli.BoolFlag{
						Name:    "save",
						Aliases: []string{"s"},
						Usage:   "Save delegations to individual files",
					},
				},
				Action: mkDelegation,
			},
			{
				Name:    "parse",
				Aliases: []string{"p"},
				Usage:   "Parse and display information about a UCAN delegation from a file or stdin",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:    "json",
						Aliases: []string{"j"},
						Usage:   "Output in JSON format",
					},
				},
				ArgsUsage: "[DELEGATION_FILE]",
				Description: "Parses a UCAN delegation from a file or stdin if no file is provided.\n" +
					"   Examples:\n" +
					"     - Parse from file: mkdelegation parse delegation.b64\n" +
					"     - Parse from stdin: cat delegation.b64 | mkdelegation parse\n" +
					"     - Parse directly: echo 'base64content' | mkdelegation parse",
				Action: parseDelegation,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func mkDelegation(cctx *cli.Context) error {
	// Don't allow both save and json flags to be used together
	if cctx.Bool("save") && cctx.Bool("json") {
		return fmt.Errorf("the --save and --json flags cannot be used together")
	}

	uploadService, err := parseOrGenerateSigner(cctx.String("upload-service-private-key"))
	if err != nil {
		return err
	}
	indexerService, err := parseOrGenerateSigner(cctx.String("indexing-service-private-key"))
	if err != nil {
		return err
	}
	storageNode, err := parseOrGenerateSigner(cctx.String("storage-node-private-key"))
	if err != nil {
		return err
	}
	indexerToUploadDelegation, err := delegation.DelegateIndexingToUpload(indexerService, uploadService)
	if err != nil {
		return fmt.Errorf("failed to create indexer to upload delegation: %w", err)
	}
	indexerToStorageDelegation, err := delegation.DelegateIndexingToStorage(indexerService, storageNode)
	if err != nil {
		return fmt.Errorf("failed to create indexer to storage delegation: %w", err)
	}
	storageToUploadDelegation, err := delegation.DelegateStorageToUpload(storageNode, uploadService)
	if err != nil {
		return fmt.Errorf("failed to create storage to upload delegation: %w", err)
	}

	// Format all keys for services
	uploadKey, err := ed25519.Format(uploadService)
	if err != nil {
		return fmt.Errorf("failed to format upload key: %w", err)
	}
	indexerKey, err := ed25519.Format(indexerService)
	if err != nil {
		return fmt.Errorf("failed to format indexer key: %w", err)
	}
	storageKey, err := ed25519.Format(storageNode)
	if err != nil {
		return fmt.Errorf("failed to format storage key: %w", err)
	}

	// Get delegation archives and encode to base64
	iub, err := io.ReadAll(indexerToUploadDelegation.Archive())
	if err != nil {
		return fmt.Errorf("failed to read indexer to upload delegation: %w", err)
	}
	isb, err := io.ReadAll(indexerToStorageDelegation.Archive())
	if err != nil {
		return fmt.Errorf("failed to read indexer to storage delegation: %w", err)
	}
	sub, err := io.ReadAll(storageToUploadDelegation.Archive())
	if err != nil {
		return fmt.Errorf("failed to read storage to upload delegation: %w", err)
	}

	iub64, err := delegation.FormatDelegation(iub)
	if err != nil {
		return fmt.Errorf("failed to format indexer to upload delegation: %w", err)
	}
	isb64, err := delegation.FormatDelegation(isb)
	if err != nil {
		return fmt.Errorf("failed to format indexer to storage delegation: %w", err)
	}
	sub64, err := delegation.FormatDelegation(sub)
	if err != nil {
		return fmt.Errorf("failed to format storage to upload delegation: %w", err)
	}

	// If save flag is set, write delegations to files
	if cctx.Bool("save") {
		if err := writeDelegationsToFiles(iub64, isb64, sub64); err != nil {
			return err
		}
		return nil
	}

	// If json flag is set, write output in JSON format to file
	if cctx.Bool("json") {
		return writeJSONToFile(
			uploadService.DID().String(), uploadKey,
			indexerService.DID().String(), indexerKey,
			storageNode.DID().String(), storageKey,
			iub64, isb64, sub64,
		)
	}

	// Otherwise, display tables
	// Create and display service information table
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Service", "DID", "Secret Key"})
	table.SetAutoWrapText(true)
	table.SetAutoMergeCells(false)
	table.SetRowLine(true)
	table.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT})
	table.SetColWidth(80) // Set sufficient width to prevent arbitrary wrapping

	table.Append([]string{"Upload Service", uploadService.DID().String(), uploadKey})
	table.Append([]string{"Indexer Service", indexerService.DID().String(), indexerKey})
	table.Append([]string{"Storage Node", storageNode.DID().String(), storageKey})

	table.Render()
	fmt.Println(tableString.String())

	// Create and display delegations table without borders and wrapping
	fmt.Println("\nDelegation Path\tBase64 Encoded UCAN")
	fmt.Println("---------------\t------------------")
	fmt.Printf("Indexer → Upload\t%s\n", iub64)
	fmt.Printf("Indexer → Storage\t%s\n", isb64)
	fmt.Printf("Storage → Upload\t%s\n", sub64)

	return nil

}

// parseOrGenerateSigner attempts to read and parse the private key from the
// provided path or generates a new key if it is the empty string.
func parseOrGenerateSigner(path string) (principal.Signer, error) {
	if path == "" {
		return ed25519.Generate()
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer f.Close()
	return parsePrivateKeyPEM(f)
}

// writeJSONToFile outputs all data in JSON format to a file in a timestamped directory
func writeJSONToFile(uploadDID, uploadKey, indexerDID, indexerKey, storageDID, storageKey, iub64, isb64, sub64 string) error {
	data := OutputData{
		Services: []ServiceInfo{
			{Name: "Upload Service", DID: uploadDID, SecretKey: uploadKey},
			{Name: "Indexer Service", DID: indexerDID, SecretKey: indexerKey},
			{Name: "Storage Node", DID: storageDID, SecretKey: storageKey},
		},
		Delegations: []DelegationInfo{
			{Path: "Indexer → Upload", UCAN: iub64},
			{Path: "Indexer → Storage", UCAN: isb64},
			{Path: "Storage → Upload", UCAN: sub64},
		},
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Create a timestamped directory name to avoid overwriting
	timestamp := time.Now().Format("20060102_150405")
	dirPath := fmt.Sprintf("delegations_%s", timestamp)

	// Create the directory
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create delegations directory: %w", err)
	}

	// Write JSON to file
	jsonPath := fmt.Sprintf("%s/output.json", dirPath)
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON to file: %w", err)
	}

	fmt.Printf("JSON output has been saved to: %s\n", jsonPath)
	return nil
}

// writeDelegationsToFiles writes delegations to individual files with timestamped directory
// and returns information about where files were written
func writeDelegationsToFiles(iub64, isb64, sub64 string) error {
	// Create a timestamped directory name to avoid overwriting
	timestamp := time.Now().Format("20060102_150405")
	dirPath := fmt.Sprintf("delegations_%s", timestamp)

	// Create the directory
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create delegations directory: %w", err)
	}

	// Write each delegation to a separate file
	iuPath := fmt.Sprintf("%s/indexer-to-upload.b64", dirPath)
	if err := os.WriteFile(iuPath, []byte(iub64), 0644); err != nil {
		return fmt.Errorf("failed to write indexer to upload delegation: %w", err)
	}

	isPath := fmt.Sprintf("%s/indexer-to-storage.b64", dirPath)
	if err := os.WriteFile(isPath, []byte(isb64), 0644); err != nil {
		return fmt.Errorf("failed to write indexer to storage delegation: %w", err)
	}

	suPath := fmt.Sprintf("%s/storage-to-upload.b64", dirPath)
	if err := os.WriteFile(suPath, []byte(sub64), 0644); err != nil {
		return fmt.Errorf("failed to write storage to upload delegation: %w", err)
	}

	// Print information about where files were saved
	fmt.Printf("Delegations saved to:\n")
	fmt.Printf("  - %s\n", iuPath)
	fmt.Printf("  - %s\n", isPath)
	fmt.Printf("  - %s\n", suPath)

	return nil
}

// parseDelegation reads a delegation from a file or stdin and displays its information
func parseDelegation(cctx *cli.Context) error {
	var info *delegation.DelegationInfo
	var err error

	// Check if a file path is provided
	if cctx.NArg() >= 1 {
		filePath := cctx.Args().First()

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
	if cctx.Bool("json") {
		jsonOutput, err := json.MarshalIndent(info, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal delegation info to JSON: %w", err)
		}
		fmt.Println(string(jsonOutput))
		return nil
	}

	// Output as a nicely formatted table
	tableString := &strings.Builder{}
	table := tablewriter.NewWriter(tableString)
	table.SetHeader([]string{"Property", "Value"})
	table.SetAutoWrapText(true)
	table.SetAutoMergeCells(false)
	table.SetRowLine(true)
	table.SetColumnAlignment([]int{tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT})
	table.SetColWidth(80) // Set sufficient width to prevent arbitrary wrapping

	// Add delegation metadata rows
	table.Append([]string{"Issuer", info.Issuer})
	table.Append([]string{"Audience", info.Audience})
	table.Append([]string{"Version", info.Version})
	table.Append([]string{"Nonce", fmt.Sprintf("%v", info.Nonce)})
	table.Append([]string{"Proofs", fmt.Sprintf("%v", info.Proofs)})
	table.Append([]string{"Signature (b64)", base64.StdEncoding.EncodeToString(info.Signature)})
	table.Append([]string{"Expiration", strconv.Itoa(info.Expiration)})
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
		capTableWriter.SetColWidth(60)

		for i, cap := range info.Capabilities {
			capTableWriter.Append([]string{fmt.Sprintf("%d", i+1), cap.Can, cap.With})
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
		factTableWriter.SetColWidth(60)

		for i, f := range info.Facts {
			factTableWriter.Append([]string{fmt.Sprintf("%d", i+1), fmt.Sprintf("%v", f)})
		}

		factTableWriter.Render()
		factTable = factTableString.String()
	} else {
		factTable = "None"
	}
	table.Append([]string{"Facts", factTable})

	table.Render()
	fmt.Println("Delegation Information:")
	fmt.Println(tableString.String())

	return nil
}

func parsePrivateKeyPEM(f io.Reader) (principal.Signer, error) {
	pemData, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading private key: %w", err)
	}
	var privateKey *crypto_ed25519.PrivateKey
	rest := pemData

	// Loop until no more blocks
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			// No more PEM blocks
			break
		}
		rest = remaining

		// Look for "PRIVATE KEY"
		if block.Type == "PRIVATE KEY" {
			parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
			}

			// We expect a ed25519 private key, cast it
			key, ok := parsedKey.(crypto_ed25519.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("the parsed key is not an ED25519 private key")
			}
			privateKey = &key
			break
		}
	}

	if privateKey == nil {
		return nil, fmt.Errorf("could not find a PRIVATE KEY block in the PEM file")
	}
	return ed25519.FromRaw(*privateKey)
}
