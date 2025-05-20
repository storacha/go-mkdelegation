# go-mkdelegation

A Go implementation of UCAN delegation tools for Storacha network services.

## Quick Start

If you'd just like to generate a set of delegations quickly, you can use `go run`:

```bash
go run github.com/storacha/go-mkdelegation@latest gen
```

## Overview

`go-mkdelegation` is a command-line tool for creating and parsing UCAN delegations between various services in the Storacha network. It's a Go port of the original JavaScript implementation.

## Installation

```bash
go install github.com/storacha/go-mkdelegation@latest
```

## Usage

The tool supports two main commands:
- `gen` (or `g`): Generate UCAN delegations between Storacha network services
- `parse` (or `p`): Parse and display information about existing UCAN delegations

### Generate Command

The `gen` command generates delegations between three services:
- Upload Service
- Indexer Service
- Storage Node

#### Output Options

The `gen` command provides these output options:

- **Default**: Displays service information and delegations in the console
- **Save to files**: Use `--save` or `-s` to save delegations as individual files
- **JSON output**: Use `--json` or `-j` to save all data in JSON format

Note: The `--save` and `--json` options cannot be used together.

#### Example Commands

Generate delegations and display in console:
```bash
mkdelegation gen
```

Save delegations to individual files:
```bash
mkdelegation gen --save
```

Example output:
```
Delegations saved to:
  - delegations_20250502_100616/indexer-to-upload.b64
  - delegations_20250502_100616/indexer-to-storage.b64
  - delegations_20250502_100616/storage-to-upload.b64
```

Save all data in JSON format:
```bash
mkdelegation gen --json
```

### Parse Command

The `parse` command allows you to analyze existing delegations by reading from a file or stdin.

#### Parse Options

- **Input from file**: Provide a path to a delegation file
- **Input from stdin**: Pipe content to the command
- **JSON output**: Use `--json` or `-j` to output in JSON format

#### Example Commands

Parse a delegation from a file:
```bash
mkdelegation parse delegations_20250502_100616/indexer-to-upload.b64
```

Parse a delegation from stdin (pipe):
```bash
cat delegations_20250502_100616/indexer-to-upload.b64 | mkdelegation parse
```

Parse with JSON output:
```bash
mkdelegation parse --json delegations_20250502_100616/indexer-to-upload.b64
```

Example output (table format):
```
Delegation Information:
+-----------------+----------------------------------------------------------------------------------------------+
|    PROPERTY     |                                            VALUE                                             |
+-----------------+----------------------------------------------------------------------------------------------+
| Issuer          | did:key:z6MkutC5yqPcSFSiPG1dZuUL5KeP1Tgrah4kAYZ4qvx3jJ7L                                     |
| Audience        | did:key:z6MkhaSkecxccgYqkVLsXCxUp66rMpYJty3CaoKLDZ1NfaK5                                     |
| Version         | 0.9.1                                                                                        |
| Nonce           |                                                                                              |
| Proofs          | []                                                                                           |
| Signature (b64) | 7aEDQILJjvH08ZtCgS+TOznNrxUHCr6TAJxnyrT6nQiJ0sMMmHCiIxJUKDNI92OoEXgCWg/wEsiVQ+VEliAau2du9Qg= |
| Expiration      | No expiration                                                                                |
| Not Before      | No not-before time                                                                           |
| Capabilities    | +---+---------------+----------------------------------------------------------+             |
|                 | | # |      CAN      |                           WITH                           |             |
|                 | +---+---------------+----------------------------------------------------------+             |
|                 | | 1 | assert/equals | did:key:z6MkutC5yqPcSFSiPG1dZuUL5KeP1Tgrah4kAYZ4qvx3jJ7L |             |
|                 | +---+---------------+----------------------------------------------------------+             |
|                 | | 2 | assert/index  | did:key:z6MkutC5yqPcSFSiPG1dZuUL5KeP1Tgrah4kAYZ4qvx3jJ7L |             |
|                 | +---+---------------+----------------------------------------------------------+             |
+-----------------+----------------------------------------------------------------------------------------------+
| Facts           | None                                                                                         |
+-----------------+----------------------------------------------------------------------------------------------+
```

### Combining Commands

You can combine the `gen` and `parse` commands to create and immediately analyze delegations:

```bash
# Generate delegations, save them, and parse one
mkdelegation gen --save && mkdelegation parse $(find delegations_* -name "indexer-to-upload.b64" | sort | tail -1)

# Generate a delegation and pipe it directly to parse (requires output extraction)
cat $(mkdelegation gen --save | grep "indexer-to-upload" | awk '{print $3}') | mkdelegation parse
```

### Output Files

Files are saved to timestamped directories to prevent overwriting existing files:

When using `--save` with the `gen` command, the following files are created in a directory named `delegations_YYYYMMDD_HHMMSS`:
- `indexer-to-upload.b64`
- `indexer-to-storage.b64`
- `storage-to-upload.b64`

When using `--json` with the `gen` command, all data is saved to:
- `delegations_YYYYMMDD_HHMMSS/output.json`

The tool will output the exact paths where files have been saved.

## Development

### Prerequisites

- Go 1.23 or later

### Building

```bash
make build
```

### Testing

```bash
make test
```

## License

See the [LICENSE](LICENSE) file for details.
