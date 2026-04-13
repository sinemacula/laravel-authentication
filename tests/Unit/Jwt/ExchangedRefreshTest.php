<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use Tests\Unit\Stubs\StubDevice;

/**
 * Unit tests for the `ExchangedRefresh` immutable result DTO.
 *
 * Asserts the constructor's promoted parameter wiring round-trips unchanged so
 * a mutation that swaps the order or types of the four fields is killed by the
 * suite.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExchangedRefresh::class)]
final class ExchangedRefreshTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The constructor exposes the supplied identity, principal, device, and
     * token result via public readonly fields.
     *
     * @return void
     */
    public function testConstructorExposesSuppliedFieldsThroughPublicProperties(): void
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class);

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = \Mockery::mock(Principal::class);

        $device = new StubDevice;
        $tokens = new RefreshResult('access-token', 'refresh-token');

        $result = new ExchangedRefresh($identity, $principal, $device, $tokens);

        self::assertSame($identity, $result->identity);
        self::assertSame($principal, $result->principal);
        self::assertSame($device, $result->device);
        self::assertSame($tokens, $result->tokens);
    }
}
