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
     * `fromKeyMap()` rejects an empty map.
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
     * `fromKeyMap()` rejects an active kid missing from the key map.
     *
     * @return void
     */
    public function testFromKeyMapRejectsUnknownActiveKid(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT active kid \'missing-kid\' is not present in the configured key map.'
            . ' Set `authentication.jwt.active_kid` to a kid that exists in `authentication.jwt.keys`.');

        JwtKeyring::fromKeyMap(
            [self::NEW_KID => self::SECRET],
            'missing-kid',
            self::ALGORITHM,
        );
    }

    /**
     * `fromKeyMap()` rejects an empty active kid.
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
     * `fromKeyMap()` rejects an empty kid inside the key map.
     *
     * @return void
     */
    public function testFromKeyMapRejectsEmptyKidInsideKeyMap(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage('JWT key map contains an empty kid. Every entry under `authentication.jwt.keys`'
            . ' must be keyed by a non-empty string.');

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
     * `fromKeyMap()` rejects empty key material.
     *
     * @return void
     */
    public function testFromKeyMapRejectsEmptyKeyMaterial(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf(
            'JWT key \'%s\' has empty material. Every kid in `authentication.jwt.keys` must map to a non-empty secret.',
            self::NEW_KID,
        ));

        JwtKeyring::fromKeyMap(
            [self::NEW_KID => ''],
            self::NEW_KID,
            self::ALGORITHM,
        );
    }

    /**
     * `fromKeyMap()` rejects `null` key material, as `env()` returns for an
     * unset variable.
     *
     * @return void
     */
    public function testFromKeyMapRejectsNullKeyMaterial(): void
    {
        $this->expectException(InvalidJwtConfigurationException::class);
        $this->expectExceptionMessage(sprintf('JWT key \'%s\' has empty material', self::NEW_KID));

        JwtKeyring::fromKeyMap(
            [self::NEW_KID => null],
            self::NEW_KID,
            self::ALGORITHM,
        );
    }

    /**
     * `fromKeyMap()` rejects a signing algorithm outside the allow-list.
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
     * Signing algorithms outside the HMAC allow-list.
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
     * `fromKeyMap()` rejects every algorithm but HMAC, naming the allow-list.
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
     * Each allow-listed algorithm with its minimum key length in bytes.
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
     * A key exactly at the algorithm's minimum length is accepted.
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
     * A key one byte short of the minimum is rejected, naming the kid,
     * algorithm and minimum.
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
     * Every kid is held to the minimum length, the inactive ones included.
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
     * Key length is measured in bytes.
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
     * A multi-kid keyring reports the configured active kid.
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
     * A numeric kid, which PHP stores as an integer key, is accepted as the
     * active kid.
     *
     * @return void
     */
    public function testFromKeyMapAcceptsNumericKid(): void
    {
        $keyring = JwtKeyring::fromKeyMap(['2026' => self::SECRET], '2026', self::ALGORITHM);

        self::assertSame('2026', $keyring->activeKid());
        self::assertSame(self::SECRET, $keyring->activeKey()->getKeyMaterial());
    }

    /**
     * `verificationKeys()` returns a map of kid to `Key`.
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
     * `activeKey()` returns the key of the configured active kid.
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
