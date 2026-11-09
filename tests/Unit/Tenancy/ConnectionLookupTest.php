<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Tenancy\ConnectionLookup;

/**
 * Unit tests for the connection a session was established through, found on the
 * first ask and kept.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionLookup::class)]
final class ConnectionLookupTest extends TestCase
{
    /**
     * Once expired, a connection not yet found is never found: asking throws
     * and the resolver never runs.
     *
     * @return void
     */
    public function testAnExpiredLookupNeverRunsItsResolver(): void
    {
        $runs   = new \ArrayObject;
        $lookup = new ConnectionLookup(static function () use ($runs): string {
            $runs->append(true);

            return 'conn-a';
        });

        $lookup->expire();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A tenant policy reads the session\'s connection while it answers, not after.');

        try {
            $lookup->connectionId();
        } finally {
            self::assertCount(0, $runs);
        }
    }

    /**
     * A connection already found stays readable after the lookup expires.
     *
     * @return void
     */
    public function testAFoundConnectionSurvivesExpiry(): void
    {
        $lookup = new ConnectionLookup(static fn (): string => 'conn-a');

        self::assertSame('conn-a', $lookup->connectionId());

        $lookup->expire();

        self::assertSame('conn-a', $lookup->connectionId());

        $nothing = new ConnectionLookup(static fn (): ?string => null);

        self::assertNull($nothing->connectionId());

        $nothing->expire();

        self::assertNull($nothing->connectionId());
    }

    /**
     * With no resolver there is no connection.
     *
     * @return void
     */
    public function testWithoutAResolverThereIsNoConnection(): void
    {
        self::assertNull((new ConnectionLookup)->connectionId());
    }

    /**
     * The resolver runs on the first ask only, and its answer is kept.
     *
     * @return void
     */
    public function testTheResolverRunsOnceOnTheFirstAsk(): void
    {
        $runs   = new \ArrayObject;
        $lookup = new ConnectionLookup(static function () use ($runs): string {
            $runs->append(true);

            return 'conn-' . count($runs);
        });

        self::assertCount(0, $runs);
        self::assertSame('conn-1', $lookup->connectionId());
        self::assertSame('conn-1', $lookup->connectionId());
        self::assertCount(1, $runs);
    }
}
