<?php

declare(strict_types = 1);

namespace Tests\Unit\ApiKeys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary;
use SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey;

/**
 * Unit tests for what is shown about an API key, and the key shown once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeySummary::class)]
#[CoversClass(IssuedApiKey::class)]
final class ApiKeySummaryTest extends TestCase
{
    /**
     * A summary is plain values, its times in ISO-8601, and no secret.
     *
     * @return void
     */
    public function testASummaryIsPlainValues(): void
    {
        $summary = self::summary();

        self::assertSame([
            'id'           => 'key-1',
            'prefix'       => 'ak_abcdefghijklmnop',
            'guard'        => 'machine',
            'name'         => 'sync',
            'scopes'       => ['read'],
            'expires_at'   => '2027-01-15T10:00:00+00:00',
            'last_used_at' => null,
            'rotated_at'   => '2027-01-13T10:00:00+00:00',
            'replaced_by'  => 'key-2',
            'revoked_at'   => '2027-01-12T10:00:00+00:00',
            'created_at'   => '2027-01-01T10:00:00+00:00',
        ], $summary->toArray());
    }

    /**
     * A key stored without a creation time shows none.
     *
     * @return void
     */
    public function testASummaryWithoutACreationTime(): void
    {
        $summary = new ApiKeySummary('key-1', 'ak_abcdefghijklmnop', 'machine', null, [], null, null, null, null, null, null);

        self::assertNull($summary->toArray()['created_at']);
        self::assertNull($summary->toArray()['expires_at']);
    }

    /**
     * An issued key holds the key for its caller, and a dump of it shows the
     * key redacted.
     *
     * @return void
     */
    public function testAnIssuedKeyRedactsTheKeyWhenDumped(): void
    {
        $key    = 'ak_abcdefghijklmnop_' . str_repeat('s', 40);
        $issued = new IssuedApiKey('key-1', $key, self::summary());

        self::assertSame($key, $issued->key);
        self::assertSame(['id' => 'key-1', 'key' => '[redacted]', 'summary' => $issued->summary], $issued->__debugInfo());
        $dumped = print_r($issued, true);

        self::assertStringNotContainsString(str_repeat('s', 40), $dumped);
        self::assertStringContainsString('[redacted]', $dumped);

        $parameter = new \ReflectionParameter([IssuedApiKey::class, '__construct'], 'key');

        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }

    /**
     * A summary of a key.
     *
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeySummary
     */
    private static function summary(): ApiKeySummary
    {
        return new ApiKeySummary(
            'key-1',
            'ak_abcdefghijklmnop',
            'machine',
            'sync',
            ['read'],
            CarbonImmutable::parse('2027-01-15 10:00:00', 'UTC'),
            null,
            CarbonImmutable::parse('2027-01-13 10:00:00', 'UTC'),
            'key-2',
            CarbonImmutable::parse('2027-01-12 10:00:00', 'UTC'),
            CarbonImmutable::parse('2027-01-01 10:00:00', 'UTC'),
        );
    }
}
