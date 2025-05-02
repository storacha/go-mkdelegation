.PHONY: build run clean install test

# Variables
BINARY_NAME=mkdelegation
GO=go

# Main build target
build:
	@echo "Building ${BINARY_NAME}..."
	@${GO} build -o ${BINARY_NAME} main.go

# Run the application
run: build
	@echo "Running ${BINARY_NAME}..."
	@./${BINARY_NAME}

# Clean build artifacts
clean:
	@echo "Cleaning up..."
	@rm -f ${BINARY_NAME}

# Install to GOPATH/bin
install:
	@echo "Installing ${BINARY_NAME}..."
	@${GO} install

# Generate JavaScript client (if needed)
gen-js:
	@echo "Generating JavaScript client..."
	@node mkdelegation.js


test:
	@${GO} test -v ./...

# Default target
default: build
