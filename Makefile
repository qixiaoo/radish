fmt:
	cargo +nightly fmt

lint:
	cargo clippy

.PHONY: fmt lint
