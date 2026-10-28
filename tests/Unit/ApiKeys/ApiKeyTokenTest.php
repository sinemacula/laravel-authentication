<?php

declare(strict_types = 1);

namespace Tests\Unit\ApiKeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyToken;

/**
 * Unit tests for the form of an API key: what is drawn, how a presented key
 * splits into its public part and secret, and how the secret is digested.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyToken::class)]
final class ApiKeyTokenTest extends TestCase
{
    /**
     * A public part is the prefix and 16 lower-case letters or digits, each of
     * the 36 drawn; a secret is 40 letters or digits, each of the 62 drawn.
     *
     * @return void
     */
    public function testDrawsFromTheWholeAlphabets(): void
    {
        $public = '';
        $secret = '';

        for ($i = 0; $i < 200; $i++) {

            $part = ApiKeyToken::newPublicPart('ak');

            self::assertMatchesRegularExpression('/^ak_[a-z0-9]{16}$/D', $part);

            $public .= substr($part, 3);

            $drawn = ApiKeyToken::newSecret();

            self::assertMatchesRegularExpression('/^[A-Za-z0-9]{40}$/D', $drawn);

            $secret .= $drawn;
        }

        self::assertCount(36, count_chars($public, 1));
        self::assertCount(62, count_chars($secret, 1));
        self::assertNotSame(ApiKeyToken::newSecret(), ApiKeyToken::newSecret());
    }

    /**
     * A key joins its public part and secret, and splits back into them.
     *
     * @return void
     */
    public function testJoinsAndSplits(): void
    {
        $secret = str_repeat('aB3', 13) . 'Z';
        $key    = ApiKeyToken::join('acme2_abcdefghij012345', $secret);

        self::assertSame('acme2_abcdefghij012345_' . $secret, $key);
        self::assertSame(['acme2_abcdefghij012345', $secret], ApiKeyToken::split($key));
        self::assertSame(['a_' . str_repeat('0', 16), str_repeat('z', 40)], ApiKeyToken::split('a_' . str_repeat('0', 16) . '_' . str_repeat('z', 40)));
        $longest = 'abcdefghijklmnop_' . str_repeat('0', 16);

        self::assertSame([$longest, str_repeat('z', 40)], ApiKeyToken::split($longest . '_' . str_repeat('z', 40)));
    }

    /**
     * Rows of `[key]` not in form.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedKeys(): iterable
    {
        $public = 'ak_abcdefghijklmnop';
        $secret = str_repeat('a', 40);

        yield from [
            'empty'              => [''],
            'public part only'   => [$public],
            'no prefix'          => ['abcdefghijklmnop_' . $secret],
            'prefix too long'    => ['abcdefghijklmnopq_abcdefghijklmnop_' . $secret],
            'prefix digit first' => ['1k_abcdefghijklmnop_' . $secret],
            'upper-case prefix'  => ['AK_abcdefghijklmnop_' . $secret],
            'short public'       => ['ak_abcdefghijklmno_' . $secret],
            'long public'        => ['ak_abcdefghijklmnopq_' . $secret],
            'upper-case public'  => ['ak_abcdefghijklmnoP_' . $secret],
            'short secret'       => [$public . '_' . substr($secret, 1)],
            'long secret'        => [$public . '_' . $secret . 'a'],
            'underscore secret'  => [$public . '_' . substr($secret, 1) . '_'],
            'leading space'      => [' ' . $public . '_' . $secret],
            'trailing newline'   => [$public . '_' . $secret . "\n"],
            'doubled underscore' => ['ak__abcdefghijklmnop_' . $secret],
        ];
    }

    /**
     * A key not in form does not split.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideMalformedKeys')]
    public function testAKeyNotInFormDoesNotSplit(string $key): void
    {
        self::assertNull(ApiKeyToken::split($key));
    }

    /**
     * A public part and a secret presented apart, as an OAuth client's id and
     * secret, are each held to their form.
     *
     * @return void
     */
    public function testHoldsAPublicPartAndASecretToTheirForm(): void
    {
        $secret = str_repeat('a', 40);

        self::assertTrue(ApiKeyToken::isWellFormed('ak_abcdefghijklmnop', $secret));
        self::assertFalse(ApiKeyToken::isWellFormed('ak_abcdefghijklmnop', $secret . "\n"));
        self::assertFalse(ApiKeyToken::isWellFormed("ak_abcdefghijklmnop\n", $secret));
        self::assertFalse(ApiKeyToken::isWellFormed('ak_abcdefghijklmno', $secret));
        self::assertFalse(ApiKeyToken::isWellFormed('ak_abcdefghijklmnop', substr($secret, 1)));
        self::assertFalse(ApiKeyToken::isWellFormed('', ''));
    }

    /**
     * A secret is digested with SHA-256, in hex.
     *
     * @return void
     */
    public function testDigestsASecretWithSha256(): void
    {
        self::assertSame(hash('sha256', 'secret'), ApiKeyToken::digest('secret'));
        self::assertSame(64, strlen(ApiKeyToken::digest(str_repeat('a', 40))));
    }
}
