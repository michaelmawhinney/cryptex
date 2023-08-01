<?php
namespace cryptex;

/**
 * Cryptex performs 2-way authenticated encryption using XChaCha20 + Poly1305.
 *
 * This class leverages the Sodium crypto library, added to PHP in version 7.2.
 * A salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES is required and should
 * be randomly generated with a secure function like random_bytes().
 *
 * @category Encryption/Decryption
 * @package Cryptex
 * @author Michael Mawhinney
 * @copyright 2023
 * @license https://opensource.org/licenses/MIT/ MIT
 * @version Release: 4.0.0
 */
final class Cryptex
{
    /**
     * Encrypt data using XChaCha20 + Poly1305 (from the Sodium crypto library)
     *
     * @param string $plaintext unencrypted data
     * @param string $key       encryption key
     * @param string $salt      salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES
     * @return string           encrypted data (hex-encoded)
     */
    public static function encrypt(string $plaintext, string $key, string $salt): string
    {
        // Generate a derived binary key
        $binKey = self::generateBinaryKey($key, $salt);

        // Generate a nonce value of the correct size
        $nonce = random_bytes(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
        );

        // Encrypt the data, prepend the nonce, and hex encode
        $ciphertext = sodium_bin2hex(
            $nonce .
            sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                '',
                $nonce,
                $binKey
            )
        );
        if ($ciphertext === false) {
            throw new Exception('Encoding failure');
        }

        // Wipe sensitive data and return the encrypted data
        sodium_memzero($plaintext);
        sodium_memzero($key);
        sodium_memzero($salt);
        return $ciphertext;
    }

    /**
     * Authenticate and decrypt data encrypted by Cryptex (XChaCha20+Poly1305)
     *
     * @param string $ciphertext    encrypted data
     * @param string $key           encryption key
     * @param string $salt          salt value
     * @return string               unencrypted data
     */
    public static function decrypt(string $ciphertext, string $key, string $salt): string
    {
        // Generate a derived binary key
        $binKey = self::generateBinaryKey($key, $salt);

        // Hex decode
        $decoded = sodium_hex2bin($ciphertext);
        if ($decoded === false) {
            throw new Exception('Decoding failure');
        }

        // Check the decoded length
        $nonceLength = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        if (strlen($decoded) < $nonceLength) {
            throw new Exception('Nonce length mismatch');
        }

        // Get the nonce value from the decoded data
        $nonce = mb_substr(
            $decoded,
            0,
            $nonceLength,
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
            $binKey
        );
        if ($plaintext === false) {
            throw new Exception('Decryption failure');
        }

        // Wipe sensitive data and return the decrypted data
        sodium_memzero($key);
        sodium_memzero($salt);
        return $plaintext;
    }

    /**
     * Generate a salt value
     *
     * @return string   random salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES
     */
    public static function generateSalt(): string
    {
        return random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
    }

    /**
     * Generate a derived binary key using Argon2id v1.3
     *
     * @param string $key   encryption key
     * @param string $salt  salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTE
     * @return string       derived binary key
     */
    private static function generateBinaryKey(string $key, string $salt): string
    {
        // Salt length requirement check
        if (strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES) {
            throw new Exception('Bad salt length');
        }

        $derivedKey = sodium_crypto_pwhash(
            SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            $key,
            $salt,
            SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );

        // Wipe sensitive data and return the derived key
        sodium_memzero($key);
        sodium_memzero($salt);
        return $derivedKey;
    }
}
