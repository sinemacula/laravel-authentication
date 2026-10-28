<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Guards\AuthenticatedBearer;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Unit tests for the method an accepted access token reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticatedBearer::class)]
final class AuthenticatedBearerTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A client credentials token reports `client_credentials`; any other
     * reports the method its device's session records, or none without a
     * device.
     *
     * @return void
     */
    public function testReportsTheMethod(): void
    {
        $admitted = new AdmittedSignIn(new PlainIdentityFixture(7), new PlainPrincipalFixture('p-1'), null);
        $client   = new AuthenticatedBearer($admitted, 'key-1', ['read']);

        self::assertSame('client_credentials', $client->method());
        self::assertSame('key-1', $client->credentialId);
        self::assertSame(['read'], $client->scopes);
        self::assertNull((new AuthenticatedBearer($admitted))->method());
        self::assertNull((new AuthenticatedBearer($admitted))->scopes);

        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getSignInMethod')->andReturn('password');

        self::assertSame('password', (new AuthenticatedBearer($admitted->on($device)))->method());
        self::assertSame('client_credentials', (new AuthenticatedBearer($admitted->on($device), 'key-1', []))->method());
    }
}
