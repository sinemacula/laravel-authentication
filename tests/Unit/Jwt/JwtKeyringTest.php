<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Firebase\JWT\Key;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;

/**
 * Unit tests for the `JwtKeyring` value object.
 *
 * Asserts the fail-closed validation surface (empty key maps, unknown active
 * kids, malformed entries, unsupported algorithms) and the shape contracts the
 * token service relies on: `verificationKeys()` returns a `kid → Key` map and
 * `activeKid()` returns the kid embedded in every issued token.
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
