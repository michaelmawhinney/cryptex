# Cryptex Documentation

## Table of Contents

* [Cryptex](#cryptex)
    * [encrypt](#encrypt)
    * [decrypt](#decrypt)

## Cryptex

Cryptex is a simple PHP class that performs 2-way authenticated (secret-key) encryption with associated data using XChaCha20 + Poly1305.



* Full name: \Cryptex


### encrypt

Encrypts data using XChaCha20+Poly1305 (from libsodium in the PHP core)

```php
Cryptex::encrypt( string $plaintext, string $key, string $salt = null ): string
```



* This method is **static**.
**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$plaintext` | **string** | unecrypted data |
| `$key` | **string** | encryption key |
| `$salt` | **string** | randomly generate a salt for maximum security |




---

### decrypt

Authenticates and decrypts data encrypted by Cryptex (XChaCha20+Poly1305)

```php
Cryptex::decrypt( string $ciphertext, string $key, string $salt = null ): string
```



* This method is **static**.
**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `$ciphertext` | **string** | encrypted data |
| `$key` | **string** | encryption key |
| `$salt` | **string** | salt used during encryption |




---



--------
> This document was automatically generated from source code comments on 2018-02-01 using [phpDocumentor](http://www.phpdoc.org/) and [cvuorinen/phpdoc-markdown-public](https://github.com/cvuorinen/phpdoc-markdown-public)
