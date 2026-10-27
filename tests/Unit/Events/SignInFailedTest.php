<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * SignInFailed event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInFailed::class)]
final class SignInFailedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Constructor retains the whole context.
     *
     * @return void
     */
    public function testStoresTheContextOnConstruction(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class);
        $tenant    = \Mockery::mock(Tenant::class);
        $device    = \Mockery::mock(Device::class);
        $client    = new ClientContext('203.0.113.7', 'agent');

        $event = new SignInFailed('api', $identity, $principal, $tenant, $device, 'password', $client, SignInFailureReason::RATE_LIMITED, 'ada@example.test', 30);

        self::assertSame('api', $event->guard);
        self::assertSame($identity, $event->identity);
        self::assertSame($principal, $event->principal);
        self::assertSame($tenant, $event->tenant);
        self::assertSame($device, $event->device);
        self::assertSame('password', $event->method);
        self::assertSame($client, $event->client);
        self::assertSame(SignInFailureReason::RATE_LIMITED, $event->reason);
        self::assertSame('ada@example.test', $event->identifier);
        self::assertSame(30, $event->retryAfter);
    }

    /**
     * The identifier and the wait default to null.
     *
     * @return void
     */
    public function testIdentifierAndWaitDefaultToNull(): void
    {
        $event = new SignInFailed('api', null, null, null, null, null, new ClientContext(null, null), SignInFailureReason::INVALID_CREDENTIALS);

        self::assertNull($event->identifier);
        self::assertNull($event->retryAfter);
    }

    /**
     * The reason enum names every way a sign-in can fail, in order.
     *
     * @return void
     */
    public function testReasonEnumCoversEveryFailurePath(): void
    {
        self::assertSame([
            'invalid_credentials',
            'method_not_allowed',
            'rate_limited',
            'account_rate_limited',
            'identity_unknown',
            'identity_inactive',
            'principal_unresolved',
            'principal_mismatch',
            'device_mismatch',
            'principal_inactive',
            'tenant_inactive',
            'principal_ineligible',
            'identifier_unverified',
            'additional_factor_required',
            'additional_factor_failed',
            'pending_invalid',
        ], array_map(static fn (SignInFailureReason $reason): string => $reason->value, SignInFailureReason::cases()));
    }
}
