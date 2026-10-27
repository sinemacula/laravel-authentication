<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Admission;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;

/**
 * Unit tests for an admitted sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdmittedSignIn::class)]
final class AdmittedSignInTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * An admitted sign-in has no device until it is given one, and giving it
     * one keeps the rest of its context and leaves the original unchanged.
     *
     * @return void
     */
    public function testContinuingOnADeviceKeepsTheContext(): void
    {
        $admitted = new AdmittedSignIn(\Mockery::mock(Identity::class), \Mockery::mock(Principal::class), \Mockery::mock(Tenant::class));
        $device   = \Mockery::mock(Device::class);

        $continued = $admitted->on($device);

        self::assertNull($admitted->device);
        self::assertSame($device, $continued->device);
        self::assertSame($admitted->identity, $continued->identity);
        self::assertSame($admitted->principal, $continued->principal);
        self::assertSame($admitted->tenant, $continued->tenant);
        self::assertNull($continued->on(null)->device);
    }
}
