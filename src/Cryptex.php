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

class EncryptionException extends \Exception {}
class EncodingException extends EncryptionException {}
class NonceLengthException extends EncryptionException {}
class DecryptionException extends EncryptionException {}
class SaltLengthException extends EncryptionException {}

final class Cryptex
{
    /**
     * @var int  required length of the nonce value
     */
    private const NONCE_LENGTH = \SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    /**
     * @var int  required length of the salt value
     */
    private const SALT_LENGTH = \SODIUM_CRYPTO_PWHASH_SALTBYTES;

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
        try {
            // Generate a derived binary key
            $binaryKey = self::generateBinaryKey($key, $salt);

            // Generate a nonce value of the correct size
            $nonce = random_bytes(self::NONCE_LENGTH);

            // Encrypt the data
            $encryptedData = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
                $plaintext,
                '',
                $nonce,
                $binaryKey
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
            sodium_memzero($binaryKey);
        }
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
        try {
            // Generate a derived binary key
            $binaryKey = self::generateBinaryKey($key, $salt);

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
                $binaryKey
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
            sodium_memzero($binaryKey);
        }
    }

    /**
     * Generate a salt value
     *
     * @return string   random salt value of length SODIUM_CRYPTO_PWHASH_SALTBYTES
     */
    public static function generateSalt(): string
    {
        return random_bytes(self::SALT_LENGTH);
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
        }
    }
}
