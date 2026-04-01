.PHONY: build test fmt lint clippy check clean doc run

build:
	cargo build

test:
	cargo test

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

clippy:
	cargo clippy -- -D warnings

lint: fmt-check clippy

check:
	cargo check

clean:
	cargo clean

doc:
	cargo doc --open

run:
	cargo run

all: fmt lint test build
