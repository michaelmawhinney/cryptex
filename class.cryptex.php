<?php

final class Cryptex
{
    /**
     * Encrypts data using XChaCha20+Poly1305 (from libsodium in the PHP core)
     *
     * @param string $plaintext unecrypted data
     * @param string $key       encryption key
     * @param string $salt      randomly generate a salt for maximum security
     * @return string
     */
    public static function encrypt(string $plaintext, string $key, string $salt = null)
    {
        // Generate a derived binary key using the provided key (and optional salt)
        $bin_key = hash_pbkdf2(
            'sha256',
            $key,
            $salt,
            10000,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            true
        );

        // Generate a nonce value of the correct size
        $nonce = random_bytes(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        // Encrypt the data, prepend the nonce, then base64 encode
        $ciphertext = base64_encode(
            $nonce.
            sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                '',
                $nonce,
                $bin_key
            )
        );
        if ($ciphertext === false) {
            throw new Exception('Encoding failure');
        }

        // Wipe the memory buffer and return the encrypted data
        sodium_memzero($plaintext);
        sodium_memzero($key);
        $salt === null || sodium_memzero($salt);
        return $ciphertext;
    }

    /**
     * Authenticates and decrypts data encrypted by Cryptex (XChaCha20+Poly1305)
     *
     * @param string $ciphertext    encrypted data
     * @param string $key           encryption key
     * @param string $salt          salt used during encryption
     * @return string
     */
    public static function decrypt(string $ciphertext, string $key, string $salt = null)
    {
        // Generate a derived binary key using the provided key (and optional salt)
        $bin_key = hash_pbkdf2(
            'sha256',
            $key,
            $salt,
            10000,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            true
        );

        // Base64 decode
        $decoded = base64_decode($ciphertext);
        if ($decoded === false) {
            throw new Exception('Decoding failure');
        }

        // Get the nonce value from the decoded data
        $nonce = mb_substr(
            $decoded,
            0,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
            '8bit'
        );

        // Get the ciphertext from the decoded data
        $ciphertext = mb_substr(
            $decoded,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
            null,
            '8bit'
        );

        // Decrypt the data
        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            '',
            $nonce,
            $bin_key
        );
        if ($plaintext === false) {
            throw new Exception('Decryption failure');
        }

        // Wipe the memory buffer and return the decrypted data
        sodium_memzero($ciphertext);
        sodium_memzero($key);
        $salt === null || sodium_memzero($salt);
        return $plaintext;
    }
}

?>
