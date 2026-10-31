<?php

declare(strict_types = 1);

namespace Tests\Unit\Admission;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Unit tests for a failed sign-in's reason and context.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Refused::class)]
final class RefusedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A refusal made before anything was established carries only its reason
     * and, for a rate limit, the wait.
     *
     * @return void
     */
    public function testARefusalBeforeVerificationCarriesNoContext(): void
    {
        $refused = new Refused(FailureReason::RATE_LIMITED, retryAfter: 42);

        self::assertSame(FailureReason::RATE_LIMITED, $refused->reason);
        self::assertNull($refused->identity);
        self::assertNull($refused->principal);
        self::assertNull($refused->tenant);
        self::assertNull($refused->device);
        self::assertSame(42, $refused->retryAfter);
    }

    /**
     * A refusal after admission keeps the admitted context, including the
     * device the sign-in was continuing on.
     *
     * @return void
     */
    public function testARefusalAfterAdmissionKeepsTheAdmittedContext(): void
    {
        $admitted = new Admitted(\Mockery::mock(Identity::class), \Mockery::mock(Principal::class), \Mockery::mock(Tenant::class));
        $device   = \Mockery::mock(Device::class);

        $refused = Refused::after(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $admitted->on($device));

        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $refused->reason);
        self::assertSame($admitted->identity, $refused->identity);
        self::assertSame($admitted->principal, $refused->principal);
        self::assertSame($admitted->tenant, $refused->tenant);
        self::assertSame($device, $refused->device);
        self::assertNull($refused->retryAfter);
        self::assertNull(Refused::after(FailureReason::DEVICE_MISMATCH, $admitted)->device);
    }
}
