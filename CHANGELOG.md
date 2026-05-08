# Changelog

## [5.0.0] - 2026-05-08

Cryptex 5.0.0 is a modernization and hardening release. It raises the supported runtime floor while preserving the existing cryptographic behavior and public API.

### Changed

- Requires PHP 8.3 or newer.
- Requires `ext-sodium`.
- Standardizes the test baseline on PHPUnit 12.
- Expands behavior coverage for success and failure cases.
- Includes hardening work in the v4 implementation.
- Reflects the repository main-branch rename to `main`.
- Aligns with the current GitHub Actions and GitHub Pages workflow setup.

### Compatibility

- The v4 public API is preserved.
- The v4 hex ciphertext format is preserved.
- External salt semantics are preserved.
- Existing v4-style ciphertext remains supported.

### Not Introduced

- No versioned ciphertext envelope.
- No base64url encoding.
- No embedded salts.
- No AAD support.
- No new public API.

### Release Notes

This release is a modernization and hardening update, not a ciphertext-format migration.
