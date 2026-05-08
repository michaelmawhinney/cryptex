<?php

declare(strict_types=1);

namespace cryptex;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SodiumException;

final class CryptexTest extends TestCase
{
    private string $key;

    private string $salt;

    private string $plaintext;

    private string $ciphertext;

    protected function setUp(): void
    {
        $this->key = '1-2-3-4-5';
        $this->salt = Cryptex::generateSalt();
        $this->plaintext = "You're a certified prince.";
        $this->ciphertext = Cryptex::encrypt($this->plaintext, $this->key, $this->salt);
    }

    public function testGenerateSaltReturnsExpectedLength(): void
    {
        $salt = Cryptex::generateSalt();

        $this->assertSame(SODIUM_CRYPTO_PWHASH_SALTBYTES, strlen($salt));
    }

    public function testEncryptDecryptRoundTrip(): void
    {
        $decrypted = Cryptex::decrypt($this->ciphertext, $this->key, $this->salt);

        $this->assertNotSame($this->plaintext, $this->ciphertext);
        $this->assertSame($this->plaintext, $decrypted);
    }

    public function testRepeatedEncryptionProducesDifferentCiphertext(): void
    {
        $otherCiphertext = Cryptex::encrypt($this->plaintext, $this->key, $this->salt);

        $this->assertNotSame($this->ciphertext, $otherCiphertext);
    }

    /**
     * @dataProvider invalidSaltLengthProvider
     */
    #[DataProvider('invalidSaltLengthProvider')]
    public function testEncryptRejectsInvalidSaltLength(string $salt): void
    {
        $this->expectException(SaltLengthException::class);

        Cryptex::encrypt($this->plaintext, $this->key, $salt);
    }

    /**
     * @dataProvider invalidSaltLengthProvider
     */
    #[DataProvider('invalidSaltLengthProvider')]
    public function testDecryptRejectsInvalidSaltLength(string $salt): void
    {
        $this->expectException(SaltLengthException::class);

        Cryptex::decrypt($this->ciphertext, $this->key, $salt);
    }

    public function testDecryptRejectsWrongKey(): void
    {
        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($this->ciphertext, 'wrong-key', $this->salt);
    }

    public function testDecryptRejectsWrongSalt(): void
    {
        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($this->ciphertext, $this->key, Cryptex::generateSalt());
    }

    public function testDecryptRejectsTamperedCiphertext(): void
    {
        $tamperedCiphertext = $this->flipLastHexNibble($this->ciphertext);

        $this->expectException(DecryptionException::class);

        Cryptex::decrypt($tamperedCiphertext, $this->key, $this->salt);
    }

    public function testDecryptRejectsMalformedHexCiphertext(): void
    {
        $this->expectException(SodiumException::class);

        Cryptex::decrypt('invalid ciphertext', $this->key, $this->salt);
    }

    public function testDecryptRejectsTooShortPayload(): void
    {
        $this->expectException(NonceLengthException::class);

        Cryptex::decrypt('aa', $this->key, $this->salt);
    }

    public function testDecryptRejectsNonceOnlyPayload(): void
    {
        $nonceOnlyPayload = sodium_bin2hex(random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES));

        $this->expectException(NonceLengthException::class);

        Cryptex::decrypt($nonceOnlyPayload, $this->key, $this->salt);
    }

    public function testDecryptRejectsNoncePlusTooShortTagPayload(): void
    {
        $payload = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES)
            . str_repeat("\x00", SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES - 1);

        $this->expectException(NonceLengthException::class);

        Cryptex::decrypt(sodium_bin2hex($payload), $this->key, $this->salt);
    }

    public function testEncryptDecryptEmptyPlaintext(): void
    {
        $plaintext = '';
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    public function testEncryptDecryptBinaryPlaintext(): void
    {
        $plaintext = "\x00\x01\x02binary\x00text\xff";
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    public function testEncryptDecryptNonAsciiPlaintext(): void
    {
        $plaintext = 'naive cafe 漢字';
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    public function testEncryptDecryptLargePlaintext(): void
    {
        $plaintext = str_repeat('x', 1000000);
        $ciphertext = Cryptex::encrypt($plaintext, $this->key, $this->salt);

        $this->assertSame($plaintext, Cryptex::decrypt($ciphertext, $this->key, $this->salt));
    }

    /**
     * @dataProvider invalidPlaintextProvider
     */
    #[DataProvider('invalidPlaintextProvider')]
    public function testEncryptRejectsInvalidPlaintextTypes($plaintext): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::encrypt($plaintext, $this->key, $this->salt);
    }

    /**
     * @dataProvider invalidCiphertextProvider
     */
    #[DataProvider('invalidCiphertextProvider')]
    public function testDecryptRejectsInvalidCiphertextTypes($ciphertext): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::decrypt($ciphertext, $this->key, $this->salt);
    }

    /**
     * @dataProvider invalidKeyProvider
     */
    #[DataProvider('invalidKeyProvider')]
    public function testEncryptRejectsInvalidKeyTypes($key): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::encrypt($this->plaintext, $key, $this->salt);
    }

    /**
     * @dataProvider invalidKeyProvider
     */
    #[DataProvider('invalidKeyProvider')]
    public function testDecryptRejectsInvalidKeyTypes($key): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::decrypt($this->ciphertext, $key, $this->salt);
    }

    /**
     * @dataProvider invalidSaltTypeProvider
     */
    #[DataProvider('invalidSaltTypeProvider')]
    public function testEncryptRejectsInvalidSaltTypes($salt): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::encrypt($this->plaintext, $this->key, $salt);
    }

    /**
     * @dataProvider invalidSaltTypeProvider
     */
    #[DataProvider('invalidSaltTypeProvider')]
    public function testDecryptRejectsInvalidSaltTypes($salt): void
    {
        $this->expectException(\TypeError::class);

        Cryptex::decrypt($this->ciphertext, $this->key, $salt);
    }

    public static function invalidPlaintextProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    public static function invalidCiphertextProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    public static function invalidKeyProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    public static function invalidSaltTypeProvider(): array
    {
        return [
            'null' => [null],
            'array' => [[]],
            'object' => [new \stdClass()],
        ];
    }

    public static function invalidSaltLengthProvider(): array
    {
        return [
            'empty' => [''],
            'short' => ['short'],
            'long' => [str_repeat('a', SODIUM_CRYPTO_PWHASH_SALTBYTES + 1)],
        ];
    }

    private function flipLastHexNibble(string $hex): string
    {
        $lastNibble = substr($hex, -1);
        $replacement = $lastNibble === '0' ? '1' : '0';

        return substr($hex, 0, -1) . $replacement;
    }
}
