<?php

declare(strict_types=1);

namespace cryptex;

/**
 * Cryptex performs 2-way authenticated encryption using XChaCha20 + Poly1305.
 *
 * This class leverages the Sodium crypto library, added to PHP in version 7.2.
 * A salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES is required and should
 * be randomly generated with the included generateSalt() function or another
 * secure function like random_bytes().
 *
 * @category Encryption/Decryption
 * @package Cryptex
 * @author Michael Mawhinney
 * @copyright 2023
 * @license https://opensource.org/licenses/MIT/ MIT
 * @version 4.0.0
 */
final class Cryptex
{
    private const NONCE_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
    private const SALT_LENGTH = \SODIUM_CRYPTO_PWHASH_SALTBYTES;
    private const TAG_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES;
    private const MINIMUM_DECODED_PAYLOAD_LENGTH = self::NONCE_LENGTH + self::TAG_LENGTH;

    /**
     * Encrypts data using XChaCha20 + Poly1305 (from the Sodium crypto library).
     *
     * @param string $plaintext Unencrypted data.
     * @param string $key Encryption key.
     * @param string $salt Salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Encrypted data (hex-encoded).
     *
     * @throws EncryptionException If the data encryption fails.
     * @throws SaltLengthException If the salt is not the expected length.
     * @throws \Random\RandomException If an error occurs while generating the nonce.
     * @throws \SodiumException If a lower-level Sodium call fails.
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
     * Authenticates and decrypts data encrypted by Cryptex (XChaCha20+Poly1305).
     *
     * @param string $ciphertext Encrypted data.
     * @param string $key Encryption key.
     * @param string $salt Salt value.
     * @return string Unencrypted data.
     *
     * @throws SaltLengthException If the salt is not the expected length.
     * @throws NonceLengthException If the decoded data is not the expected length.
     * @throws DecryptionException If the data decryption fails.
     * @throws \SodiumException If the ciphertext is malformed hex or a lower-level Sodium call fails.
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
     * Generates a salt value.
     *
     * @return string Random salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     *
     * @throws \Random\RandomException If an error occurs while generating the salt value.
     */
    public static function generateSalt(): string
    {
        return random_bytes(self::SALT_LENGTH);
    }

    /**
     * Generates a derived binary key using Argon2id v1.3.
     *
     * @param string $key Encryption key.
     * @param string $salt Salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Derived binary key.
     *
     * @throws SaltLengthException If the salt is not the expected length.
     * @throws \SodiumException If an error occurs while generating the derived binary key.
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

    /**
     * @throws SaltLengthException If the salt is not the expected length.
     */
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

/**
 * Class EncryptionException
 * Custom exception class for encryption errors.
 */
class EncryptionException extends \Exception {}

/**
 * Class EncodingException
 * Custom exception class for encoding errors.
 */
class EncodingException extends EncryptionException {}

/**
 * Class NonceLengthException
 * Custom exception class for nonce length errors.
 */
class NonceLengthException extends EncryptionException {}

/**
 * Class DecryptionException
 * Custom exception class for decryption errors.
 */
class DecryptionException extends EncryptionException {}

/**
 * Class SaltLengthException
 * Custom exception class for salt length errors.
 */
class SaltLengthException extends EncryptionException {}
