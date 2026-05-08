<?php

declare(strict_types=1);

namespace cryptex;

/**
 * Authenticated encryption with XChaCha20-Poly1305.
 *
 * Use a salt of length SODIUM_CRYPTO_PWHASH_SALTBYTES when deriving the key.
 */
final class Cryptex
{
    private const NONCE_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    private const SALT_LENGTH = \SODIUM_CRYPTO_PWHASH_SALTBYTES;
    private const TAG_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
    private const MINIMUM_DECODED_PAYLOAD_LENGTH = self::NONCE_LENGTH + self::TAG_LENGTH;

    /**
     * Encrypts plaintext with a key derived from the supplied salt.
     *
     * Returns a hex-encoded nonce concatenated with the authenticated ciphertext.
     *
     * @param string $plaintext Plaintext to encrypt.
     * @param string $key Passphrase or key material.
     * @param string $salt Salt of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Hex-encoded nonce and ciphertext.
     * @throws EncryptionException If encryption fails.
     * @throws SaltLengthException If the salt length is invalid.
     * @throws \Random\RandomException If nonce generation fails.
     * @throws \SodiumException If key derivation or encryption fails.
     */
    public static function encrypt(string $plaintext, string $key, string $salt): string
    {
        $derivedKey = '';
        try {
            $derivedKey = self::generateDerivedKey($key, $salt);
            $nonce = random_bytes(self::NONCE_LENGTH);
            $encryptedPayload = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                '',
                $nonce,
                $derivedKey
            );

            if ($encryptedPayload === false) {
                throw new EncryptionException('Failed to encrypt the data');
            }

            return sodium_bin2hex($nonce . $encryptedPayload);
        } finally {
            self::wipeBuffer($derivedKey);
        }
    }

    /**
     * Decrypts a hex-encoded nonce and ciphertext produced by encrypt().
     *
     * @param string $ciphertext Hex-encoded nonce and ciphertext.
     * @param string $key Passphrase or key material.
     * @param string $salt Salt of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Plaintext.
     * @throws SaltLengthException If the salt length is invalid.
     * @throws NonceLengthException If the decoded payload is too short.
     * @throws DecryptionException If authentication fails.
     * @throws \SodiumException If hex decoding or key derivation fails.
     */
    public static function decrypt(string $ciphertext, string $key, string $salt): string
    {
        $derivedKey = '';
        try {
            $derivedKey = self::generateDerivedKey($key, $salt);
            $decodedPayload = sodium_hex2bin($ciphertext);

            if (strlen($decodedPayload) < self::MINIMUM_DECODED_PAYLOAD_LENGTH) {
                throw new NonceLengthException('Decoded data is shorter than the minimum payload length');
            }

            $nonce = substr($decodedPayload, 0, self::NONCE_LENGTH);
            $encryptedPayload = substr($decodedPayload, self::NONCE_LENGTH);

            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $encryptedPayload,
                '',
                $nonce,
                $derivedKey
            );

            if ($plaintext === false) {
                throw new DecryptionException('Failed to decrypt the data');
            }

            return $plaintext;
        } finally {
            self::wipeBuffer($derivedKey);
        }
    }

    /**
     * Generates a random salt.
     *
     * @return string Random salt of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @throws \Random\RandomException If salt generation fails.
     */
    public static function generateSalt(): string
    {
        return random_bytes(self::SALT_LENGTH);
    }

    /**
     * Derives the AEAD key from the supplied key material and salt.
     *
     * @param string $key Passphrase or key material.
     * @param string $salt Salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Derived binary key.
     * @throws SaltLengthException If the salt is not the expected length.
     * @throws \SodiumException If key derivation fails.
     */
    private static function generateDerivedKey(string $key, string $salt): string
    {
        self::assertValidSaltLength($salt);

        return sodium_crypto_pwhash(
            \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
            $key,
            $salt,
            \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
            \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
            \SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
        );
    }

    /** @throws SaltLengthException If the salt length is invalid. */
    private static function assertValidSaltLength(string $salt): void
    {
        if (strlen($salt) !== self::SALT_LENGTH) {
            throw new SaltLengthException('Salt is not the expected length');
        }
    }

    private static function wipeBuffer(string &$buffer): void
    {
        if ($buffer === '') {
            return;
        }

        sodium_memzero($buffer);
    }
}

/** Thrown when encryption fails. */
class EncryptionException extends \Exception {}

/** Thrown when encoding or decoding fails. */
class EncodingException extends EncryptionException {}

/** Thrown when the decoded payload is too short. */
class NonceLengthException extends EncryptionException {}

/** Thrown when authentication fails. */
class DecryptionException extends EncryptionException {}

/** Thrown when the supplied salt length is invalid. */
class SaltLengthException extends EncryptionException {}
