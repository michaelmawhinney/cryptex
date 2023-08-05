<?php
namespace cryptex;

use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * CryptexTest performs unit testing for the Cryptex class.
 *
 * @category Tests
 * @package Cryptex
 * @author Michael Mawhinney
 * @copyright 2023
 * @license https://opensource.org/licenses/MIT/ MIT
 * @version Release: 4.0.0
 */
final class CryptexTest extends TestCase
{
    /**
     * @var string Key for encryption and decryption tests.
     */
    private $key;

    /**
     * @var string Salt for encryption and decryption tests.
     */
    private $salt;

    /**
     * @var int Length of the salt value.
     */
    private $saltLength;

    /**
     * @var string Plaintext string for encryption and decryption tests.
     */
    private $plaintext;

    /**
     * @var string Ciphertext string for encryption and decryption tests.
     */
    private $ciphertext;

    /**
     * Sets up each test by initializing required variables and generating encrypted data for decryption tests.
     */
    protected function setUp(): void
    {
        // Access the private vars with reflection
        $reflection = new ReflectionClass(Cryptex::class);
        $this->saltLength = $reflection->getReflectionConstant('SALT_LENGTH')->getValue();

        // Set the remaining vars
        $this->key = '1-2-3-4-5';
        $this->salt = Cryptex::generateSalt();
        $this->plaintext = "You're a certified prince.";
        $this->ciphertext = Cryptex::encrypt($this->plaintext, $this->key, $this->salt);
    }

    /**
     * Tests the `generateSalt()` method.
     */
    public function testGenerateSalt(): void
    {
        $this->assertIsInt($this->saltLength);
        $this->assertIsString($this->salt);
        $this->assertEquals($this->saltLength, strlen($this->salt));
    }

    /**
     * Tests the `encrypt()` and `decrypt()` methods with valid inputs.
     */
    public function testEncryptDecrypt(): void
    {
        $this->assertIsString($this->ciphertext);
        $this->assertNotEquals($this->plaintext, $this->ciphertext);

        $decrypted = Cryptex::decrypt($this->ciphertext, $this->key, $this->salt);
        $this->assertEquals($this->plaintext, $decrypted);
    }

    /**
     * Tests the `encrypt()` and `decrypt()` methods with invalid input values.
     */
    public function testEncryptDecryptWithInvalidInput(): void
    {
        $this->expectException(\TypeError::class);

        $invalidInputs = [null, '', [], new \stdClass(), true];
        foreach ($invalidInputs as $invalidInput) {
            Cryptex::encrypt($invalidInput, $this->key, $this->salt);
            Cryptex::decrypt($invalidInput, $this->key, $this->salt);
        }
    }

    /**
     * Tests the `encrypt()` and `decrypt()` methods with invalid key or salt.
     */
    public function testEncryptDecryptWithInvalidKeyOrSalt(): void
    {
        $this->expectException(\TypeError::class);
        $invalidInputs = [null, '', [], new \stdClass(), true, 'invalid'];
        foreach ($invalidInputs as $invalidInput) {
            Cryptex::encrypt($this->ciphertext, $invalidInput, $this->salt);
            Cryptex::decrypt($this->ciphertext, $invalidInput, $this->salt);
            Cryptex::encrypt($this->ciphertext, $this->key, $invalidInput);
            Cryptex::decrypt($this->ciphertext, $this->key, $invalidInput);
        }
    }

    /**
     * Tests the `decrypt()` method with invalid ciphertext.
     */
    public function testDecryptWithInvalidCiphertext(): void
    {
        $this->expectException(\Exception::class);
        Cryptex::decrypt('invalid ciphertext', $this->key, $this->salt);
    }

    /**
     * Tests the `encrypt()` and `decrypt()` methods with a large plaintext string.
     */
    public function testLargePlaintext(): void
    {
        $largePlaintext = str_repeat('x', 1000000); // 1 million characters
        $ciphertext = Cryptex::encrypt($largePlaintext, $this->key, $this->salt);
        $decrypted = Cryptex::decrypt($ciphertext, $this->key, $this->salt);

        $this->assertEquals($largePlaintext, $decrypted);
    }

    /**
     * Tests the `encrypt()` and `decrypt()` methods with a plaintext string that contains non-alphanumeric characters.
     */
    public function testNonAlphanumericCharacters(): void
    {
        $nonAlphanumericPlaintext = '!@#$%^&*(){}[]:;"<>,.?/~`|-_=+\\';
        $ciphertext = Cryptex::encrypt($nonAlphanumericPlaintext, $this->key, $this->salt);
        $decrypted = Cryptex::decrypt($ciphertext, $this->key, $this->salt);

        $this->assertEquals($nonAlphanumericPlaintext, $decrypted);
    }

    /**
     * Tests the `encrypt()` and `decrypt()` methods with a key that contains non-alphanumeric characters.
     */
    public function testKeyNonAlphanumericCharacters(): void
    {
        $nonAlphanumericKey = '!@#$%^&*(){}[]:;"<>,.?/~`|-_=+\\';
        $ciphertext = Cryptex::encrypt($this->plaintext, $nonAlphanumericKey, $this->salt);
        $decrypted = Cryptex::decrypt($ciphertext, $nonAlphanumericKey, $this->salt);

        $this->assertEquals($this->plaintext, $decrypted);
    }
}
