<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Guards\AuthenticatedBearer;
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
     * reports the method its session records, or none without a session.
     *
     * @return void
     */
    public function testReportsTheMethod(): void
    {
        $admitted = new Admitted(new PlainIdentityFixture(7), new PlainPrincipalFixture('p-1'), null);
        $client   = new AuthenticatedBearer($admitted, 'key-1', ['read']);

        self::assertSame('client_credentials', $client->method());
        self::assertSame('key-1', $client->credentialId);
        self::assertSame(['read'], $client->scopes);
        self::assertNull((new AuthenticatedBearer($admitted))->method());
        self::assertNull((new AuthenticatedBearer($admitted))->scopes);

        $session = \Mockery::mock(Session::class);
        $session->shouldReceive('getSignInMethod')->andReturn('password');

        self::assertSame('password', (new AuthenticatedBearer($admitted->on($session)))->method());
        self::assertSame('client_credentials', (new AuthenticatedBearer($admitted->on($session), 'key-1', []))->method());
    }
}
