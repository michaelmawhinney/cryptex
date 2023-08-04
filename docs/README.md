# Cryptex Documentation

## Table of Contents

* [Cryptex](#cryptex)
    * [encrypt](#encrypt)
    * [decrypt](#decrypt)
    * [generateSalt](#generateSalt)

## Cryptex

Cryptex performs 2-way authenticated encryption using XChaCha20 + Poly1305.

This class leverages the Sodium crypto library, added to PHP in version 7.2.
A salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES is required and should
be randomly generated with the included generateSalt() function or another
secure function like random_bytes().

* Full name: Cryptex


### encrypt

Encrypt data using XChaCha20 + Poly1305 (from the Sodium crypto library)

```php
Cryptex::encrypt( string $plaintext, string $key, string $salt ): string
```



* This method is **static**.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$plaintext` | **string** | unencrypted data |
| `$key` | **string** | encryption key |
| `$salt` | **string** | salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES |


**Return Value:**

encrypted data (hex-encoded)



---

### decrypt

Authenticate and decrypt data encrypted by Cryptex (XChaCha20+Poly1305)

```php
Cryptex::decrypt( string $ciphertext, string $key, string $salt ): string
```



* This method is **static**.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$ciphertext` | **string** | encrypted data |
| `$key` | **string** | encryption key |
| `$salt` | **string** | salt value |


**Return Value:**

unencrypted data



---

### generateSalt

Securely generate a random salt value of the required length

```php
Cryptex::generateSalt(): string
```



* This method is **static**.

**Return Value:**

salt value (binary string)
