# go-mkdelegation

A Go implementation of UCAN delegation tools for Storacha network services.

## Overview

`go-mkdelegation` is a command-line tool for creating UCAN delegations between various services in the Storacha network. It's a Go port of the original JavaScript implementation.

## Installation

```bash
go install github.com/storacha/go-mkdelegation@latest
```

## Usage

The tool supports generating UCAN delegations between Storacha network services with the following options:

### Output Options

The tool provides these output options:

- **Default**: Displays service information and delegations in the console
- **Save to files**: Use `--save` or `-s` to save delegations as individual files
- **JSON output**: Use `--json` or `-j` to save all data in JSON format

Note: The `--save` and `--json` options cannot be used together.

### Example Commands

Generate delegations and display in console:
```bash
go-mkdelegation
```

Save delegations to individual files:
```bash
go-mkdelegation --save
```

Save all data in JSON format:
```bash
go-mkdelegation --json
```

### Output Files

Files are saved to timestamped directories to prevent overwriting existing files:

When using `--save`, the following files are created in a directory named `delegations_YYYYMMDD_HHMMSS`:
- `indexer-to-upload.b64`
- `indexer-to-storage.b64`
- `storage-to-upload.b64`

When using `--json`, all data is saved to:
- `delegations_YYYYMMDD_HHMMSS/output.json`

The tool will output the exact paths where files have been saved.

## Development

### Prerequisites

- Go 1.24 or later

### Building

```bash
go build -o go-mkdelegation
```

### Testing

```bash
go test ./...
```

## License

See the [LICENSE](LICENSE) file for details.