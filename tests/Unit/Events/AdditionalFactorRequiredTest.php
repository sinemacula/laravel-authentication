<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use Carbon\CarbonImmutable;
use Illuminate\Queue\SerializesModels;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * AdditionalFactorRequired event unit tests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdditionalFactorRequired::class)]
final class AdditionalFactorRequiredTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The event carries the context of the sign-in held for a factor, and its
     * expiry, but nothing to complete it with.
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
        $expiresAt = CarbonImmutable::createStrict(2026, 4, 6, 12, 5, 0);

        $event = new AdditionalFactorRequired('api', $identity, $principal, $tenant, $device, 'password', $client, $expiresAt);

        self::assertSame('api', $event->guard);
        self::assertSame($identity, $event->identity);
        self::assertSame($principal, $event->principal);
        self::assertSame($tenant, $event->tenant);
        self::assertSame($device, $event->device);
        self::assertSame('password', $event->method);
        self::assertSame($client, $event->client);
        self::assertSame($expiresAt, $event->expiresAt);
        self::assertSame(
            ['guard', 'identity', 'principal', 'tenant', 'device', 'method', 'client', 'expiresAt'],
            array_map(static fn (\ReflectionProperty $property): string => $property->getName(), (new \ReflectionClass($event))->getProperties()),
        );
    }

    /**
     * Queued listeners get the models re-fetched, as Laravel's
     * `SerializesModels` does.
     *
     * @return void
     */
    public function testSerializesItsModels(): void
    {
        self::assertContains(SerializesModels::class, class_uses(AdditionalFactorRequired::class));
    }
}
