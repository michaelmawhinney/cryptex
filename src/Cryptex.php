<?php
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
 * @version Release: 4.0.0
 */

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

/**
 * Class Cryptex
 * Handles encryption and decryption with XChaCha20 + Poly1305 (Sodium crypto library).
 */
final class Cryptex
{
    /**
     * @var int  Required length of the nonce value
     */
    private const NONCE_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    /**
     * @var int  Required length of the salt value
     */
    private const SALT_LENGTH = \SODIUM_CRYPTO_PWHASH_SALTBYTES;

    /**
     * Encrypts data using XChaCha20 + Poly1305 (from the Sodium crypto library).
     *
     * @param string $plaintext Unencrypted data.
     * @param string $key Encryption key.
     * @param string $salt Salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Encrypted data (hex-encoded).
     *
     * @throws EncryptionException If the data encryption fails.
     */
    public static function encrypt(string $plaintext, string $key, string $salt): string
    {
        try {
            // Generate a derived binary key
            $derivedKey = self::generateDerivedKey($key, $salt);

            // Generate a nonce value of the correct size
            $nonce = random_bytes(self::NONCE_LENGTH);

            // Encrypt the data
            $encryptedData = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                '',
                $nonce,
                $derivedKey
            );
            if ($encryptedData === false) {
                throw new EncryptionException('Failed to encrypt the data');
            }

            // Prepend the nonce, and hex encode
            $ciphertext = sodium_bin2hex($nonce . $encryptedData);

            // Return the encrypted data
            return $ciphertext;
        } catch (Exception $e) {
            // Rethrow the exception
            throw $e;
        } finally {
            // Wipe sensitive data
            sodium_memzero($plaintext);
            sodium_memzero($key);
            sodium_memzero($salt);
            sodium_memzero($derivedKey);
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
     * @throws NonceLengthException If the decoded data is not the expected length.
     * @throws DecryptionException If the data decryption fails.
     */
    public static function decrypt(string $ciphertext, string $key, string $salt): string
    {
        try {
            // Generate a derived binary key
            $derivedKey = self::generateDerivedKey($key, $salt);

            // Hex decode
            $decoded = sodium_hex2bin($ciphertext);

            // Check the decoded length
            if (strlen($decoded) < self::NONCE_LENGTH) {
                throw new NonceLengthException('Decoded data is not the expected length');
            }

            // Get the nonce value from the decoded data
            $nonce = mb_substr(
                $decoded,
                0,
                self::NONCE_LENGTH,
                '8bit'
            );

            // Get the ciphertext from the decoded data
            $ciphertext = mb_substr(
                $decoded,
                self::NONCE_LENGTH,
                null,
                '8bit'
            );

            // Decrypt the data
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                '',
                $nonce,
                $derivedKey
            );
            if ($plaintext === false) {
                throw new DecryptionException('Failed to decrypt the data');
            }

            // Return the decrypted data
            return $plaintext;
        } catch (Exception $e) {
            // Rethrow the exception
            throw $e;
        } finally {
            // Wipe sensitive data
            sodium_memzero($key);
            sodium_memzero($salt);
            sodium_memzero($derivedKey);
        }
    }

    /**
     * Generates a salt value.
     *
     * @return string Random salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     *
     * @throws Exception If an error occurs while generating the salt value.
     */
    public static function generateSalt(): string
    {
        try {
            $salt = random_bytes(self::SALT_LENGTH);
            return $salt;
        } catch (Exception $e) {
            throw $e;
        } finally {
            sodium_memzero($salt);
        }
    }

    /**
     * Generates a derived binary key using Argon2id v1.3.
     *
     * @param string $key Encryption key.
     * @param string $salt Salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES.
     * @return string Derived binary key.
     *
     * @throws SaltLengthException If the salt is not the expected length.
     * @throws Exception If an error occurs while generating the derived binary key.
     */
    private static function generateDerivedKey(string $key, string $salt): string
    {
        try {
            // Salt length requirement check
            if (strlen($salt) !== self::SALT_LENGTH) {
                throw new SaltLengthException('Salt is not the expected length');
            }

            // Generate the derived binary key
            $derivedKey = sodium_crypto_pwhash(
                SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES,
                $key,
                $salt,
                SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
                SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13
            );

            // Return the derived binary key
            return $derivedKey;
        } catch (Exception $e) {
            // Rethrow the exception
            throw $e;
        } finally {
            // Wipe sensitive data
            sodium_memzero($key);
            sodium_memzero($salt);
            sodium_memzero($derivedKey);
        }
    }
}
