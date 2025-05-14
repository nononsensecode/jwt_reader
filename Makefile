# Makefile for building jwt_reader for Linux and Windows

# The default target
.PHONY: build
build: build-linux build-windows

# Build for Linux (native)
.PHONY: build-linux
build-linux:
	cargo build --release

# Build for Windows (cross-compiling)
.PHONY: build-windows
build-windows:
	cargo build --release --target x86_64-pc-windows-gnu

# Clean build artifacts
.PHONY: clean
clean:
	cargo clean
