# go-mkdelegation

A Go implementation of UCAN (User Controlled Authorization Networks) delegation tools.

## Quick Start

Generate a UCAN delegation:

```bash
mkdelegation gen -i issuer-key.pem -a did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK -s -c "*/*"
```

## Overview

`go-mkdelegation` is a command-line tool for creating and parsing UCAN delegations. 
It allows you to generate delegations between principals with specific capabilities and parse existing delegations to inspect their contents, including recursive parsing of proof delegations.

## Installation

```bash
go install github.com/storacha/go-mkdelegation@latest
```

## Usage

The tool supports two main commands:
- `gen` (or `g`): Generate UCAN delegations with specified capabilities
- `parse` (or `p`): Parse and display information about existing UCAN delegations

### Generate Command

The `gen` command creates UCAN delegations from an issuer to an audience with specified capabilities.

#### Required Parameters

- **Issuer Private Key**: Use `--issuer-private-key` (or `-i`) to specify the path to an Ed25519 private key in PEM format
- **Audience DID**: Use `--audience-did-key` (or `-a`) to specify the audience's DID (must be in did:key format)
- **Capabilities**: Use `--capabilities` (or `-c`) to specify one or more capabilities to delegate (can be specified multiple times)

#### Optional Parameters

- **Issuer DID Web**: Use `--issuer-did-web` (or `-w`) to wrap the issuer with a did:web identity
- **Expiration**: Use `--expiration` (or `-e`) to set expiration time in UTC seconds since Unix epoch
- **Skip Validation**: Use `--skip-capability-validation` (or `-s`) to skip validation of capabilities against known set

#### Known Capabilities

The tool validates capabilities against the following known Storacha service capabilities:
- `assert/equals`, `assert/relation`, `assert/partition`, `assert/index`, `assert/inclusion`, `assert/location`
- `blob/accept`, `blob/allocate`
- `claim/cache`
- `http/put`
- `pdp/accept`, `pdp/info`
- `space/blob/add`, `space/blob/get`, `space/blob/list`, `space/blob/remove`, `space/blob/replicate`
- `ucan/conclude`

To use custom capabilities not in this list, use the `--skip-capability-validation` flag.

#### Example Commands

Generate a delegation with basic capabilities:
```bash
mkdelegation gen \
  -i issuer-key.pem \
  -a did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK \
  -c "blob/accept" \
  -c "blob/allocate"
```

Generate a delegation with all capabilities (using wildcard):
```bash
mkdelegation gen \
  -i issuer-key.pem \
  -a did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK \
  -c "*/*" \
  -s
```

Generate a delegation with expiration:
```bash
mkdelegation gen \
  -i issuer-key.pem \
  -a did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK \
  -c "assert/equals" \
  -e 1735689600  # Expires on Jan 1, 2025
```

Generate a delegation with did:web issuer:
```bash
mkdelegation gen \
  -i issuer-key.pem \
  -w "did:web:example.com" \
  -a did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK \
  -c "http/put"
```

### Parse Command

The `parse` command allows you to analyze existing delegations by reading from a file or stdin. It supports recursive parsing of proof delegations, displaying the complete delegation chain.

#### Parse Options

- **Input from file**: Provide a path to a delegation file
- **Input from stdin**: Pipe content to the command
- **JSON output**: Use `--json` or `-j` to output in JSON format

#### Example Commands

Parse a delegation from a file:
```bash
mkdelegation parse delegation.b64
```

Parse a delegation from stdin:
```bash
cat delegation.b64 | mkdelegation parse
```

Parse from a generated delegation:
```bash
mkdelegation gen -i key.pem -a did:key:z6Mkh... -c "blob/accept" | mkdelegation parse
```

Parse with JSON output:
```bash
mkdelegation parse --json delegation.b64
```

#### Example Output

Table format (default):
```
Delegation Information:
+-----------------+----------------------------------------------------------------------------------------------+
|    PROPERTY     |                                            VALUE                                             |
+-----------------+----------------------------------------------------------------------------------------------+
| Issuer          | did:key:z6MkutC5yqPcSFSiPG1dZuUL5KeP1Tgrah4kAYZ4qvx3jJ7L                                     |
| Audience        | did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK                                     |
| Version         | 0.9.1                                                                                        |
| Nonce           |                                                                                              |
| Signature (b64) | 7aEDQILJjvH08ZtCgS+TOznNrxUHCr6TAJxnyrT6nQiJ0sMMmHCiIxJUKDNI92OoEXgCWg/wEsiVQ+VEliAau2du9Qg= |
| Expiration      | 1735689600 (1 Jan 25 00:00 UTC)                                                             |
| Not Before      | 0                                                                                            |
| Capabilities    | +---+---------------+----------------------------------------------------------+             |
|                 | | # |      CAN      |                           WITH                           |             |
|                 | +---+---------------+----------------------------------------------------------+             |
|                 | | 1 | blob/accept   | did:key:z6MkutC5yqPcSFSiPG1dZuUL5KeP1Tgrah4kAYZ4qvx3jJ7L |             |
|                 | +---+---------------+----------------------------------------------------------+             |
|                 | | 2 | blob/allocate | did:key:z6MkutC5yqPcSFSiPG1dZuUL5KeP1Tgrah4kAYZ4qvx3jJ7L |             |
|                 | +---+---------------+----------------------------------------------------------+             |
+-----------------+----------------------------------------------------------------------------------------------+
| Facts           | None                                                                                         |
+-----------------+----------------------------------------------------------------------------------------------+
```

When a delegation contains proofs (other delegations), they are parsed recursively and displayed as nested tables:

```
| Proof Delegations | === Proof Delegation 1 ===                                                                 |
|                   | +-----------------+------------------------------------------------------------------------+  |
|                   | |    PROPERTY     |                                VALUE                                 |  |
|                   | +-----------------+------------------------------------------------------------------------+  |
|                   | | Issuer          | did:key:z6MkqNJSEiVgztATfHBfE2bamdCxsmLm52tB8j8QWHdftDr3           |  |
|                   | | Audience        | did:key:z6MkutC5yqPcSFSiPG1dZuUL5KeP1Tgrah4kAYZ4qvx3jJ7L           |  |
|                   | | ...             | ...                                                                |  |
|                   | +-----------------+------------------------------------------------------------------------+  |
```

### Output Format

#### Base64-encoded CAR Format

Generated delegations are output as multibase-base64-encoded CIDv1 with embedded CAR data. This format:
- Contains the complete delegation archive
- Is self-describing with the CID
- Can be parsed by any UCAN-compatible tool
- Preserves the delegation chain including any proofs

### Combining Commands

Generate and immediately parse a delegation:
```bash
mkdelegation gen -i key.pem -a did:key:z6Mkh... -c "blob/accept" | mkdelegation parse
```

Save a delegation and parse it:
```bash
mkdelegation gen -i key.pem -a did:key:z6Mkh... -c "blob/accept" > my-delegation.b64
mkdelegation parse my-delegation.b64
```

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
