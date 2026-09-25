## Description

Describe what this PR does and why. Link to any related issues (e.g., `Fixes #123`).

## Type of Change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Refactoring (no functional changes)
- [ ] Documentation update
- [ ] CI/build change

## Checklist

- [ ] [CLA signed](CLA.md) (the bot will prompt you on your first PR)
- [ ] Tests pass (`cargo test --locked -- --test-threads=1`); new `tests/*.rs` files are added to `.github/workflows/ci.yml`
- [ ] Clippy passes with the CI flags (`cargo clippy --workspace --all-targets -- -D clippy::correctness -D clippy::suspicious -A deprecated`) and no new warnings are introduced
- [ ] Code is formatted (`cargo fmt --all`)
- [ ] New functionality has tests
- [ ] Every `unsafe` block has a `// SAFETY:` comment
- [ ] Dependency changes pass `cargo deny --workspace --all-features check`; any new advisory suppression is in `deny.toml` with a reason and expiry
- [ ] Documentation describes what the code actually does (mark planned features as "not yet implemented")
- [ ] No key material in logs or debug output (use `[REDACTED]`)
- [ ] CHANGELOG.md updated (for user-facing changes)
