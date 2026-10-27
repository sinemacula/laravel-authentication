<?php

declare(strict_types = 1);

namespace Tests\Unit\RateLimiting;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\RateLimiting\CounterKeys;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

/**
 * Unit tests for the keys the attempt limiter stores its counters under.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CounterKeys::class)]
final class CounterKeysTest extends TestCase
{
    /** @var string Application key the keys are derived from. */
    private const string APP_KEY = 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=';

    /**
     * A counter's key is the HMAC-SHA256 of the guard, flow, scope and value
     * joined by NUL bytes, under a key derived from the application key: the
     * same on every call, 64 hexadecimal characters, and not the plain digest
     * anyone could recompute from a guessed value.
     *
     * @return void
     */
    public function testACountersKeyIsAKeyedDigestOfItsParts(): void
    {
        $keys     = self::keys(self::APP_KEY);
        $secret   = hash_hmac('sha256', 'sinemacula/laravel-authentication rate limit counters', self::APP_KEY, true);
        $expected = hash_hmac('sha256', implode("\0", ['api', 'sign_in', 'per_ip', '203.0.113.7']), $secret);

        self::assertSame($expected, $keys->counter('api', AttemptFlow::SIGN_IN, 'per_ip', '203.0.113.7'));
        self::assertSame($expected, $keys->counter('api', AttemptFlow::SIGN_IN, 'per_ip', '203.0.113.7'));
        self::assertNotSame(hash('sha256', implode("\0", ['api', 'sign_in', 'per_ip', '203.0.113.7'])), $expected);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $expected);
    }

    /**
     * An account's key is the keyed digest of the flow, `per_account` and the
     * account, without the guard, so every guard counts in one counter.
     *
     * @return void
     */
    public function testAnAccountsKeyLeavesTheGuardOut(): void
    {
        $keys   = self::keys(self::APP_KEY);
        $secret = hash_hmac('sha256', 'sinemacula/laravel-authentication rate limit counters', self::APP_KEY, true);

        $account = implode("\0", ['row', 'users', '5']);

        self::assertSame(hash_hmac('sha256', implode("\0", ['refresh', 'per_account', $account]), $secret), $keys->account(AttemptFlow::REFRESH, $account));
        self::assertNotSame($keys->account(AttemptFlow::SIGN_IN, 'account'), $keys->account(AttemptFlow::REFRESH, 'account'));
    }

    /**
     * Another application key gives every counter another key, so rotating it
     * starts the counters afresh.
     *
     * @return void
     */
    public function testAnotherApplicationKeyGivesOtherKeys(): void
    {
        $before = self::keys(self::APP_KEY);
        $after  = self::keys('base64:' . base64_encode(str_repeat('k', 32)));

        $counter = static fn (CounterKeys $keys): string => $keys->counter('api', AttemptFlow::SIGN_IN, 'per_identifier', 'ada@example.test');

        self::assertNotSame($counter($before), $counter($after));
        self::assertNotSame($before->account(AttemptFlow::SIGN_IN, 'account'), $after->account(AttemptFlow::SIGN_IN, 'account'));
    }

    /**
     * Application keys that cannot key the counters.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMissingApplicationKeys(): iterable
    {
        yield from [
            'unset'      => [null],
            'empty'      => [''],
            'not a text' => [['base64:abc']],
        ];
    }

    /**
     * Without an application key the counters cannot be keyed, so the limiter
     * fails closed rather than store digests anyone could reverse.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('provideMissingApplicationKeys')]
    public function testAMissingApplicationKeyFailsClosed(mixed $key): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The attempt limiter keys its counters with the application key; set `app.key`.');

        self::keys($key)->counter('api', AttemptFlow::SIGN_IN, 'per_ip', '203.0.113.7');
    }

    /**
     * Build the keys under the application key.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authentication\RateLimiting\CounterKeys
     */
    private static function keys(mixed $key): CounterKeys
    {
        return new CounterKeys(new Repository(['app' => ['key' => $key]]));
    }
}
