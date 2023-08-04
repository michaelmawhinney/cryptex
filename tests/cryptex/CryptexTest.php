<?php

namespace cryptex;

use PHPUnit\Framework\TestCase;
use ReflectionClass;

/**
 * Class CryptexTest
 *
 * This class is used to perform unit testing for the Cryptex class.
 *
 * @package Cryptex
 */
final class CryptexTest extends TestCase
{
    private $key;
    private $salt;
    private $saltLength;
    private $plaintext;
    private $ciphertext;

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

    public function testGenerateSalt(): void
    {
        $this->assertIsInt($this->saltLength);
        $this->assertIsString($this->salt);
        $this->assertEquals($this->saltLength, strlen($this->salt));
    }

    public function testEncryptDecrypt(): void
    {
        $this->assertIsString($this->ciphertext);
        $this->assertNotEquals($this->plaintext, $this->ciphertext);

        $decrypted = Cryptex::decrypt($this->ciphertext, $this->key, $this->salt);
        $this->assertEquals($this->plaintext, $decrypted);
    }

    public function testEncryptDecryptWithInvalidInput(): void
    {
        $this->expectException(\TypeError::class);

        $invalidInputs = [null, '', [], new \stdClass(), true];
        foreach ($invalidInputs as $invalidInput) {
            Cryptex::encrypt($invalidInput, $this->key, $this->salt);
            Cryptex::decrypt($invalidInput, $this->key, $this->salt);
        }
    }

    public function testDecryptWithInvalidCiphertext(): void
    {
        $this->expectException(\Exception::class);
        Cryptex::decrypt('invalid ciphertext', $this->key, $this->salt);
    }

    public function testDecryptWithInvalidKey(): void
    {
        $this->expectException(\Exception::class);
        Cryptex::decrypt($this->ciphertext, 'invalid key', $this->salt);
    }

    public function testDecryptWithInvalidSalt(): void
    {
        $this->expectException(\Exception::class);
        Cryptex::decrypt($this->ciphertext, $this->key, 'invalid salt');
    }
}
