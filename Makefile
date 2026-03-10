.PHONY: fmt clippy test test-fast test-prop build check clean

# Run all checks (same as CI)
check: fmt clippy test
	@echo "All checks passed."

# Format check (no modification)
fmt:
	cargo fmt --all --check

# Format fix
fmt-fix:
	cargo fmt --all

# Lint
clippy:
	cargo clippy --all-targets --features cli -- -D warnings

# Fast tests (unit + integration, ~3s)
test-fast:
	cargo test --lib --test adversarial --test outside_in --test golden_tests --features cli

# Full tests including property-based (~2min)
test: test-fast
	cargo test --test property_tests

# CLI tests
test-cli:
	cargo test --test cli_tests --features cli

# Build release binary
build:
	cargo build --release --features cli

# Install locally
install:
	cargo install --path . --force --features cli

# Clean build artifacts
clean:
	cargo clean
