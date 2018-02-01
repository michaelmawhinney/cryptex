<?php

final class Cryptex
{
    public static function encrypt(string $plaintext, string $key, string $salt = null)
    {
        $bin_key = hash_pbkdf2(
            'sha256',
            $key,
            $salt,
            10000,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            true
        );

        $nonce = random_bytes(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

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

        sodium_memzero($plaintext);
        sodium_memzero($key);
        $salt === null || sodium_memzero($salt);
        return $ciphertext;
    }

    public static function decrypt(string $ciphertext, string $key, string $salt = null)
    {
        $bin_key = hash_pbkdf2(
            'sha256',
            $key,
            $salt,
            10000,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            true
        );

        $decoded = base64_decode($ciphertext);
        if ($decoded === false) {
            throw new Exception('Decoding failure');
        }

        $nonce = mb_substr(
            $decoded,
            0,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
            '8bit'
        );

        $ciphertext = mb_substr(
            $decoded,
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES,
            null,
            '8bit'
        );

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $ciphertext,
            '',
            $nonce,
            $bin_key
        );
        if ($plaintext === false) {
            throw new Exception('Decryption failure');
        }

        sodium_memzero($ciphertext);
        sodium_memzero($key);
        $salt === null || sodium_memzero($salt);
        return $plaintext;
    }
}

?>
