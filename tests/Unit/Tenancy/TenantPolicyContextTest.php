<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Unit tests for what a tenant authentication policy is asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantPolicyContext::class)]
final class TenantPolicyContextTest extends TestCase
{
    /**
     * A context built without a closure has no connection.
     *
     * @return void
     */
    public function testAContextBuiltWithoutAClosureHasNoConnection(): void
    {
        self::assertNull(self::context()->connectionId());
    }

    /**
     * A context judges a call unless it is built to judge a session again.
     *
     * @return void
     */
    public function testAContextJudgesACallByDefault(): void
    {
        self::assertFalse(self::context()->rejudging);
    }

    /**
     * The closure runs only when the connection is asked for, and once however
     * often it is: a `null` answer is kept too.
     *
     * @return void
     */
    public function testTheConnectionIsFoundWhenFirstAskedAndOnce(): void
    {
        $runs    = new \ArrayObject;
        $context = self::context(static function () use ($runs): string {
            $runs->append(true);

            return 'conn-a';
        });

        self::assertCount(0, $runs);
        self::assertSame('conn-a', $context->connectionId());
        self::assertSame('conn-a', $context->connectionId());
        self::assertCount(1, $runs);

        $nulls   = new \ArrayObject;
        $nothing = self::context(static function () use ($nulls): ?string {
            $nulls->append(true);

            return null;
        });

        self::assertNull($nothing->connectionId());
        self::assertNull($nothing->connectionId());
        self::assertCount(1, $nulls);
    }

    /**
     * Once the check ends, an unresolved connection is never found and asking
     * throws; a found one stays readable.
     *
     * @return void
     */
    public function testExpiryEndsAnUnresolvedConnectionOnly(): void
    {
        $unresolved = self::context(static fn (): string => 'conn-a');
        $resolved   = self::context(static fn (): string => 'conn-b');

        self::assertSame('conn-b', $resolved->connectionId());

        $unresolved->expire();
        $resolved->expire();

        self::assertSame('conn-b', $resolved->connectionId());

        $this->expectException(\LogicException::class);

        $unresolved->connectionId();
    }

    /**
     * A context over plain fixtures, with the closure given.
     *
     * @param  ?\Closure(): ?string  $connectionId
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext
     */
    private static function context(?\Closure $connectionId = null): TenantPolicyContext
    {
        return new TenantPolicyContext('api', new PlainIdentityFixture(7), new PlainPrincipalFixture(7), new PlainTenantFixture(1), null, $connectionId);
    }
}
