<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Firebase\JWT\Key;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;

/**
 * Unit tests for the `JwtKeyring` value object.
 *
 * Asserts the fail-closed validation surface (empty key maps, unknown active
 * kids, malformed entries, short keys, unsupported algorithms) and the shape
 * contracts the token service relies on: `verificationKeys()` returns a
 * `kid → Key` map and `activeKid()` returns the kid embedded in every issued
 * token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtKeyring::class)]
final class JwtKeyringTest extends TestCase
{
    /** @var string Test secret used as key material across the tests. */
    private const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string HMAC algorithm used across the keyring tests. */
    private const string ALGORITHM = 'HS256';

    /** @var string Kid used by the current-generation key in rotation tests. */
    private const string NEW_KID = '2026-04';

    /** @var string Kid used by the previous-generation key in rotation tests. */
    private const string OLD_KID = '2026-03';

    /**
     * Asserts `fromKeyMap()` rejects an empty map with the typed configuration
     * exception.
     *
     * @return void
     */
    public function testFromKeyMapRejectsEmptyMap(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT key map is empty. Set `authentication.jwt.keys` to a kid -> secret map of at least one entry.');

        JwtKeyring::fromKeyMap([], self::NEW_KID, self::ALGORITHM);
    }

    /**
     * Asserts `fromKeyMap()` rejects an active kid that does not appear in the
     * supplied key map.
     *
     * @return void
     */
    public function testFromKeyMapRejectsUnknownActiveKid(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT active kid \'missing-kid\' is not present');

        JwtKeyring::fromKeyMap(
            [self::NEW_KID => self::SECRET],
            'missing-kid',
            self::ALGORITHM,
        );
    }

    /**
     * Asserts `fromKeyMap()` rejects an empty active-kid string even when the
     * supplied map is non-empty.
     *
     * @return void
     */
    public function testFromKeyMapRejectsEmptyActiveKid(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);

        JwtKeyring::fromKeyMap(
            [self::NEW_KID => self::SECRET],
            '',
            self::ALGORITHM,
        );
    }

    /**
     * Asserts `fromKeyMap()` rejects a `kid -> secret` map containing an
     * empty-string kid alongside a valid one. The active-kid presence check at
     * the top of the factory passes (the active kid is the non-empty entry), so
     * the iteration in `buildKeyMap()` surfaces the empty-kid guard.
     *
     * @return void
     */
    public function testFromKeyMapRejectsEmptyKidInsideKeyMap(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT key map contains an empty kid');

        JwtKeyring::fromKeyMap(
            [
                self::NEW_KID => self::SECRET,
                ''            => self::SECRET . '!',
            ],
            self::NEW_KID,
            self::ALGORITHM,
        );
    }

    /**
     * Asserts `fromKeyMap()` rejects an entry whose secret material is the
     * empty string - every kid must map to real material.
     *
     * @return void
     */
    public function testFromKeyMapRejectsEmptyKeyMaterial(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf('JWT key \'%s\' has empty material', self::NEW_KID));

        JwtKeyring::fromKeyMap(
            [self::NEW_KID => ''],
            self::NEW_KID,
            self::ALGORITHM,
        );
    }

    /**
     * Asserts `fromKeyMap()` rejects an entry whose secret material is `null`
     * - `env()` returns `null` for unset variables, so the runtime guard must
     * catch this case as well as the empty string to fail closed with a
     * friendly message naming the offending kid.
     *
     * @return void
     */
    public function testFromKeyMapRejectsNullKeyMaterial(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf('JWT key \'%s\' has empty material', self::NEW_KID));

        // `fromKeyMap` is declared `array<array-key, mixed>` precisely so the
        // fail-closed guard can reject the null payload at runtime rather than
        // via a static-analysis hint.
        JwtKeyring::fromKeyMap(
            [self::NEW_KID => null],
            self::NEW_KID,
            self::ALGORITHM,
        );
    }

    /**
     * Asserts `fromKeyMap()` rejects a signing algorithm that is not on the
     * supported allow-list - typos and weak settings must fail at boot rather
     * than at the first encode/decode call.
     *
     * @return void
     */
    public function testFromKeyMapRejectsUnsupportedAlgorithm(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT algorithm \'HS526\' is not supported');

        JwtKeyring::fromKeyMap([self::NEW_KID => self::SECRET], self::NEW_KID, 'HS526');
    }

    /**
     * Data provider listing signing algorithms outside the HMAC allow-list,
     * including the asymmetric families that were previously accepted.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRejectedAlgorithms(): iterable
    {
        yield from [
            'RS256'          => ['RS256'],
            'RS384'          => ['RS384'],
            'RS512'          => ['RS512'],
            'ES256'          => ['ES256'],
            'ES384'          => ['ES384'],
            'EdDSA'          => ['EdDSA'],
            'none'           => ['none'],
            'lowercase-hmac' => ['hs256'],
        ];
    }

    /**
     * Asserts `fromKeyMap()` accepts only HMAC algorithms: one key per kid both
     * signs and verifies, which an asymmetric key pair cannot do, so every
     * other algorithm is rejected with the allow-list in the message.
     *
     * @param  string  $algorithm
     * @return void
     */
    #[DataProvider('provideRejectedAlgorithms')]
    public function testFromKeyMapRejectsAlgorithmOutsideHmacAllowList(string $algorithm): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage("JWT algorithm '{$algorithm}' is not supported. Set `authentication.jwt.algorithm` to one of: HS256, HS384, HS512.");

        JwtKeyring::fromKeyMap([self::NEW_KID => self::SECRET], self::NEW_KID, $algorithm);
    }

    /**
     * Data provider pairing each allow-listed algorithm with its minimum key
     * length in bytes (the HMAC digest size).
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideAlgorithmMinimumKeyLengths(): iterable
    {
        yield from [
            'HS256' => ['HS256', 32],
            'HS384' => ['HS384', 48],
            'HS512' => ['HS512', 64],
        ];
    }

    /**
     * Asserts a key exactly at the algorithm's minimum length is accepted.
     *
     * @param  string  $algorithm
     * @param  int  $minimumBytes
     * @return void
     */
    #[DataProvider('provideAlgorithmMinimumKeyLengths')]
    public function testFromKeyMapAcceptsKeyAtAlgorithmMinimumLength(string $algorithm, int $minimumBytes): void
    {
        $material = str_repeat('k', $minimumBytes);

        $keyring = JwtKeyring::fromKeyMap([self::NEW_KID => $material], self::NEW_KID, $algorithm);

        self::assertSame($material, $keyring->activeKey()->getKeyMaterial());
    }

    /**
     * Asserts a key one byte shorter than the algorithm's minimum is rejected
     * with a message naming the kid, the algorithm, and the minimum length.
     *
     * @param  string  $algorithm
     * @param  int  $minimumBytes
     * @return void
     */
    #[DataProvider('provideAlgorithmMinimumKeyLengths')]
    public function testFromKeyMapRejectsKeyShorterThanAlgorithmMinimum(string $algorithm, int $minimumBytes): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf(
            'JWT key \'%s\' is too short for %s: it must be at least %d bytes. Set every kid in `authentication.jwt.keys` to a random value of at least %d bytes.',
            self::NEW_KID,
            $algorithm,
            $minimumBytes,
            $minimumBytes,
        ));

        JwtKeyring::fromKeyMap([self::NEW_KID => str_repeat('k', $minimumBytes - 1)], self::NEW_KID, $algorithm);
    }

    /**
     * Asserts every kid is held to the minimum length, not just the active one,
     * so a short retired key cannot linger in the verification map.
     *
     * @return void
     */
    public function testFromKeyMapRejectsShortKeyForInactiveKid(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf('JWT key \'%s\' is too short for HS256', self::OLD_KID));

        JwtKeyring::fromKeyMap(
            [
                self::NEW_KID => self::SECRET,
                self::OLD_KID => 'short-old-key',
            ],
            self::NEW_KID,
            self::ALGORITHM,
        );
    }

    /**
     * Asserts key length is measured in bytes, matching the HMAC key size: 16
     * two-byte characters make a 32-byte key, which HS256 accepts.
     *
     * @return void
     */
    public function testFromKeyMapMeasuresKeyLengthInBytes(): void
    {
        $material = str_repeat('é', 16);

        $keyring = JwtKeyring::fromKeyMap([self::NEW_KID => $material], self::NEW_KID, self::ALGORITHM);

        self::assertSame($material, $keyring->activeKey()->getKeyMaterial());
    }

    /**
     * Asserts a multi-kid keyring reports the configured active kid so the
     * token service can embed it in the JWT header.
     *
     * @return void
     */
    public function testFromKeyMapExposesActiveKid(): void
    {
        $keyring = JwtKeyring::fromKeyMap(
            [
                self::NEW_KID => self::SECRET,
                self::OLD_KID => self::SECRET . '!',
            ],
            self::NEW_KID,
            self::ALGORITHM,
        );

        self::assertSame(self::NEW_KID, $keyring->activeKid());
    }

    /**
     * Asserts `verificationKeys()` returns a `kid → Key` map so php-jwt picks
     * the correct key from each token's `kid` header.
     *
     * @return void
     */
    public function testFromKeyMapReturnsKeyMapForVerification(): void
    {
        $keyring = JwtKeyring::fromKeyMap(
            [
                self::NEW_KID => self::SECRET,
                self::OLD_KID => self::SECRET . '!',
            ],
            self::NEW_KID,
            self::ALGORITHM,
        );

        $verificationKeys = $keyring->verificationKeys();

        self::assertCount(2, $verificationKeys);
        self::assertArrayHasKey(self::NEW_KID, $verificationKeys);
        self::assertArrayHasKey(self::OLD_KID, $verificationKeys);
        self::assertInstanceOf(Key::class, $verificationKeys[self::NEW_KID]);
        self::assertInstanceOf(Key::class, $verificationKeys[self::OLD_KID]);
    }

    /**
     * Asserts `activeKey()` returns the `Key` keyed by the configured active
     * kid (not some other entry in the map).
     *
     * @return void
     */
    public function testActiveKeyReturnsKeyForConfiguredActiveKid(): void
    {
        $newSecret = 'secret-for-' . self::NEW_KID . '-with-32-bytes!';
        $oldSecret = 'secret-for-' . self::OLD_KID . '-with-32-bytes!';

        $keyring = JwtKeyring::fromKeyMap(
            [
                self::NEW_KID => $newSecret,
                self::OLD_KID => $oldSecret,
            ],
            self::OLD_KID,
            self::ALGORITHM,
        );

        self::assertSame($oldSecret, $keyring->activeKey()->getKeyMaterial());
    }
}
