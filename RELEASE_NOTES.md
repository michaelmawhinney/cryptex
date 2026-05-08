# Cryptex v5.0.0 Release Notes

Cryptex 5.0.0 is a modernization and hardening release.

## Highlights

- Requires PHP 8.3 or newer.
- Requires `ext-sodium`.
- Uses a modernized PHPUnit 12 test baseline.
- Expands behavior coverage around encryption and decryption.
- Preserves the v4 public API.
- Preserves the v4 hex ciphertext format.
- Preserves external salt semantics.
- Includes hardening work in the v4 implementation.
- Reflects the repository main-branch rename to `main`.
- Matches the current GitHub Actions and GitHub Pages workflow setup.

## Compatibility

Existing v4-style ciphertext continues to work with the same API. This release does not introduce a versioned ciphertext envelope, base64url encoding, embedded salts, AAD, or a new public API.

## Summary

This is a major release for the new PHP/platform baseline, not a ciphertext-format migration.
