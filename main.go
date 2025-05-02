package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"

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
		Usage: "Create UCAN delegations for various service interactions",
		Flags: []cli.Flag{
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
		Action: func(cctx *cli.Context) error {
			// Don't allow both save and json flags to be used together
			if cctx.Bool("save") && cctx.Bool("json") {
				return fmt.Errorf("the --save and --json flags cannot be used together")
			}

			uploadService, err := ed25519.Generate()
			if err != nil {
				return err
			}
			indexerService, err := ed25519.Generate()
			if err != nil {
				return err
			}
			storageNode, err := ed25519.Generate()
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
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
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