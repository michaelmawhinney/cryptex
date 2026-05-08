# AGENTS.md

## Project intent

Cryptex is a small PHP library for authenticated symmetric encryption using PHP's Sodium extension.

The goal of this repository is not novelty, cleverness, or framework-style abstraction. The goal is boring correctness: a small, modern, secure, maintainable PHP encryption API whose behavior is explicit, tested, documented, and unsurprising.

Prefer simple, auditable code over clever code.

## Working principles

- Keep the library small.
- Keep the public API minimal and intentional.
- Make security-relevant behavior explicit.
- Preserve backward compatibility unless a major-version change is clearly justified.
- Prefer standard PHP, Composer, PHPUnit, and Sodium primitives.
- Avoid dependencies unless they clearly improve correctness, safety, or maintainability.
- Avoid speculative abstractions, service containers, interfaces, traits, magic methods, reflection, global state, or framework coupling.
- Every change should make the package easier to trust.

## Current package shape

- Language: PHP.
- Package manager: Composer.
- Namespace: `cryptex\`.
- Main source file: `src/Cryptex.php`.
- Tests: `tests/`.
- The package should remain usable as a lightweight Composer dependency.

Do not restructure the repository into an application. This is a library.

## Security model

Cryptex should provide authenticated encryption for caller-supplied plaintext using libsodium.

Expected properties:

- Confidentiality: ciphertext should not reveal plaintext without the correct secret.
- Integrity: tampering with ciphertext, nonce, tag, version, or envelope data must cause decryption failure.
- Misuse resistance where reasonable: unsafe states should be rejected early.
- Clear failure behavior: decryption must never return unauthenticated plaintext.
- Explicit format handling: ciphertext formats must be versioned or clearly recognized.

Out of scope:

- Protecting against compromised hosts.
- Protecting secrets after the PHP process or server is compromised.
- Inventing custom cryptographic primitives.
- Password policy enforcement.
- Key storage or secret management.

## Cryptography rules

Use Sodium primitives directly.

Allowed primitives:

- Authenticated encryption: `sodium_crypto_aead_xchacha20poly1305_ietf_*`.
- Password/key derivation when deriving from passphrases: `sodium_crypto_pwhash()` with Argon2id.
- Randomness: `random_bytes()`.
- Constant-time comparisons where comparisons are needed: `hash_equals()` or Sodium equivalents.
- Encoding: Sodium encoding helpers where appropriate.

Do not:

- Implement custom encryption, MAC, padding, KDF, nonce generation, or random generation.
- Use OpenSSL as a replacement unless there is a deliberate documented migration reason.
- Use unauthenticated encryption modes.
- Silently truncate keys, salts, nonces, or ciphertexts.
- Accept malformed ciphertext.
- Return partially decrypted data.
- Log secrets, plaintext, derived keys, salts, nonces, or raw binary payloads.

## API design

The public API should be small, explicit, and stable.

Prefer these public methods:

- `Cryptex::encrypt(...)`
- `Cryptex::decrypt(...)`
- `Cryptex::generateSalt(...)`

Only add public methods when they solve a real compatibility or safety problem.

When changing ciphertext formats:

- New encryption output should use a versioned format.
- Decryption may support legacy formats when necessary.
- Legacy behavior must be tested.
- Format detection must be deterministic and fail closed.
- Unknown versions must throw a clear exception.

If legacy v4 hex ciphertext remains supported, either:

- keep `decrypt()` able to read it safely, or
- provide an explicit `decryptLegacyHex()` method.

Do not make ambiguous APIs where the same parameter means different things without documentation.

## Backward compatibility

Before changing behavior, identify whether the change affects:

- ciphertext format,
- salt handling,
- key derivation,
- exception types,
- PHP version requirements,
- Composer package requirements,
- public method signatures.

Breaking changes require:

- clear documentation,
- changelog entry,
- migration notes,
- tests for old and new behavior,
- a major version bump.

Prefer compatibility paths when they do not compromise security or clarity.

## Implementation standards

Use modern PHP style.

Required:

- `declare(strict_types=1);`
- explicit parameter and return types,
- strict comparisons where applicable,
- binary-safe string handling,
- clear exception classes,
- no dead code,
- no redundant catch-and-rethrow blocks,
- no uninitialized variables in cleanup paths,
- no cleanup that destroys values returned to the caller.

Use `substr()` for binary slicing. Do not introduce an `mbstring` dependency for binary operations.

Composer requirements must declare required PHP extensions, including at minimum:

- `ext-sodium`

Only declare `ext-mbstring` if the code truly requires it, which it should not for core encryption.

## Memory handling

Be careful with `sodium_memzero()`.

Do:

- wipe derived keys and other temporary secret buffers when practical.
- guard cleanup so it only runs on initialized strings.
- avoid wiping values that must be returned to the caller.

Do not:

- call `sodium_memzero()` on uninitialized variables.
- wipe `$plaintext` immediately before returning it.
- wipe caller-owned inputs in a way that creates surprising PHP behavior.
- let cleanup errors mask the original cryptographic error.

Memory wiping in PHP has limitations. Use it carefully and modestly, not performatively.

## Error handling

Failure modes should be explicit.

Use project-specific exceptions where useful:

- `EncryptionException`
- `DecryptionException`
- `SaltLengthException`
- `NonceLengthException`
- `EncodingException` if encoding/decoding failures are meaningfully distinct.

Catch `\Throwable` only when wrapping lower-level failures with clearer library exceptions.

Do not use unqualified `Exception` inside the `cryptex` namespace unless intentionally referring to `cryptex\Exception`.

Decryption failures should not reveal unnecessary detail. It is acceptable to distinguish malformed input from authentication failure in tests and internal code, but public errors should remain safe and clear.

## Ciphertext format guidance

Prefer a self-contained, versioned ciphertext envelope for new formats.

A reasonable modern format is:

version || salt || nonce || ciphertext_and_tag

Then encode with a transport-safe encoding such as base64url without padding.

Document:

- version byte,
- salt length,
- nonce length,
- tag length,
- minimum decoded length,
- encoding variant,
- legacy format behavior.

Validate decoded length before slicing.

Minimum length for an XChaCha20-Poly1305 envelope must account for:

- version byte,
- salt,
- nonce,
- authentication tag.

Malformed payloads must fail closed.

## Testing requirements

Tests are not optional. Changes are incomplete without tests.

At minimum, cover:

- successful encrypt/decrypt round trip,
- different ciphertext for repeated encryption of the same plaintext,
- wrong key fails,
- wrong salt fails where applicable,
- tampered ciphertext fails,
- tampered nonce fails,
- tampered tag fails,
- malformed encoding fails,
- too-short payload fails,
- unsupported version fails,
- empty plaintext succeeds,
- binary plaintext succeeds,
- large plaintext succeeds,
- non-ASCII plaintext succeeds,
- legacy ciphertext compatibility if supported,
- generated salt length,
- invalid salt length,
- exception types for expected failure modes.

Avoid tests that stop after the first case inside a loop. Use data providers where appropriate.

Tests should be deterministic except where randomness is the behavior under test.

## Static analysis and tooling

Add standard tooling only when it materially improves confidence.

Recommended project commands:

- `composer test`
- `composer lint`
- `composer stan`
- `composer cs-check`

Reasonable tools:

- PHPUnit for tests.
- PHPStan or Psalm for static analysis.
- PHP-CS-Fixer or PHP_CodeSniffer for style.
- Composer validation.

Tooling should be configured in the repo and runnable locally.

Do not add heavyweight frameworks or unrelated build systems.

## CI expectations

CI should run on pull requests and pushes.

CI should check:

- Composer validation.
- dependency installation.
- PHP syntax linting.
- unit tests.
- static analysis.
- coding style check if configured.

Test against currently supported PHP versions for the package. Do not claim support for PHP versions not covered by CI.

Keep CI boring and readable.

## Documentation requirements

Documentation should explain behavior, not market the package.

Update docs when changing:

- installation requirements,
- PHP version support,
- required extensions,
- public API,
- ciphertext format,
- salt handling,
- key handling,
- migration path,
- exception behavior,
- test/tool commands.

Security documentation should include:

- what Cryptex protects,
- what it does not protect,
- key and salt guidance,
- storage guidance,
- tamper behavior,
- legacy compatibility notes.

Examples must be correct and copy-pasteable.

Do not include toy secrets in examples without clearly marking them as examples.

## Performance guidance

This library should be efficient but not at the expense of security.

- Avoid unnecessary dependencies.
- Avoid unnecessary allocations where clarity is not harmed.
- Do not prematurely optimize cryptographic code.
- Keep KDF cost parameters defensible and documented.
- Do not weaken Argon2id settings to make tests faster unless tests explicitly mock or isolate that cost.

Performance-sensitive changes should be justified in comments, tests, or documentation.

## Dependency policy

Dependencies increase maintenance and supply-chain risk.

Before adding a runtime dependency, ask:

- Is this necessary?
- Is it well maintained?
- Does PHP or Sodium already provide this?
- Can this be implemented more clearly in a few lines?
- Does it increase the attack surface?

Runtime dependencies should be close to zero.

Development dependencies are acceptable when they improve tests, style, or analysis.

## Coding style

Prefer code that looks inevitable.

- Short methods.
- Clear names.
- No clever branching.
- No hidden global state.
- No magic constants without names.
- No comments that merely repeat code.
- Comments should explain security decisions, format decisions, or non-obvious constraints.
- Use constants for sizes, versions, and algorithm parameters.
- Keep exception messages clear and stable.

## Commit and PR expectations

Each PR should include:

- summary of changes,
- security rationale if behavior changed,
- backward compatibility notes,
- test coverage notes,
- commands run,
- migration notes if applicable.

Do not mix unrelated refactors with security-sensitive behavior changes unless necessary.

Prefer small, reviewable commits.

## Definition of done

A change is done only when:

- public behavior is intentional,
- security-sensitive behavior is documented,
- tests cover success and failure paths,
- Composer metadata is accurate,
- CI/tooling passes,
- examples are updated,
- legacy behavior is preserved or migration is documented,
- the code is simpler or more trustworthy than before.

The best final result is a library that feels uneventful: small surface area, obvious control flow, explicit formats, strong tests, and no surprises.
