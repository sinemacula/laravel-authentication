<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;

/**
 * Feature tests for the context every bind reports: the whole triple is bound
 * before any event fires, the events carry the guard, the request's client, the
 * tenant and the device's sign-in method, and `authenticateAs()` binds without
 * reporting a sign-in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversClass(BindsContextualState::class)]
final class AbstractGuardEventContextTest extends AbstractGuardTestCase
{
    /**
     * `authenticateAs()` binds the triple and fires only `Authenticated`,
     * `PrincipalAssigned` and `DeviceAuthenticated`: no `Validated`, no
     * `Login`.
     *
     * @return void
     */
    public function testAuthenticateAsReportsTheBindButNoSignIn(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $device    = $this->mockDevice();
        $events    = $this->recordEvents();
        $guard     = $this->makeGuard();

        $guard->authenticateAs($identity, $principal, $device);

        self::assertSame([Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class], self::classes($events));
        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertSame($device, $guard->device());
    }

    /**
     * `authenticateAs()` replaces whatever was bound before and settles the
     * request, so a device bound earlier never survives a bind without one and
     * the request's own credential is not resolved afterwards.
     *
     * @return void
     */
    public function testAuthenticateAsReplacesThePriorBindAndSettlesTheRequest(): void
    {
        $this->recordEvents();

        $guard = $this->makeGuard();

        $guard->login($this->mockIdentity(), $this->mockPrincipal(), $this->mockDevice());

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();

        $guard->authenticateAs($identity, $principal);

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertNull($guard->device());
    }

    /**
     * Every bind sets the whole triple before its first event, so a listener on
     * `Authenticated` already reads the principal and the device the bind
     * reports.
     *
     * @return void
     */
    public function testAListenerOnAuthenticatedSeesTheWholeContext(): void
    {
        $guard     = $this->makeGuard();
        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $device    = $this->mockDevice();
        $seen      = null;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use ($guard, &$seen): void {
                if (!$event instanceof Authenticated) {
                    return;
                }

                $seen = [$guard->principal(), $guard->device()];
            });

        $guard->login($identity, $principal, $device);

        self::assertSame([$principal, $device], $seen);
    }

    /**
     * `PrincipalAssigned` and `DeviceAuthenticated` of one bind carry the same
     * context: the guard, the request's client, the identity, principal, the
     * tenant the principal names, the device, and the method the device's
     * session records.
     *
     * @return void
     */
    public function testTheBindEventsCarryTheWholeContext(): void
    {
        $this->request->shouldReceive('ip')->andReturn('203.0.113.9');
        $this->request->shouldReceive('userAgent')->andReturn('Agent/1.0');

        $tenant = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn(5);

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $device    = $this->mockDevice();

        $principal->shouldReceive('getTenant')->andReturn($tenant);
        $device->shouldReceive('getSignInMethod')->andReturn('password');

        $events = $this->recordEvents();

        $this->makeGuard()->login($identity, $principal, $device);

        [, , , $assigned, $authenticated] = $events->getArrayCopy();

        self::assertInstanceOf(PrincipalAssigned::class, $assigned);
        self::assertInstanceOf(DeviceAuthenticated::class, $authenticated);
        self::assertSame($assigned->context, $authenticated->context);

        $context = $assigned->context;

        self::assertSame(self::GUARD_NAME, $context->guard);
        self::assertSame('203.0.113.9', $context->client->ip);
        self::assertSame('Agent/1.0', $context->client->userAgent);
        self::assertSame($identity, $context->identity);
        self::assertSame($principal, $context->principal);
        self::assertSame($tenant, $context->tenant);
        self::assertSame('5', $context->tenantId);
        self::assertSame($device, $context->device);
        self::assertSame('password', $context->method);
    }

    /**
     * `login()` reports a sign-in: `Validated` and `Login` come before the bind
     * events.
     *
     * @return void
     */
    public function testLoginReportsTheSignInBeforeTheBind(): void
    {
        $events = $this->recordEvents();

        $this->makeGuard()->login($this->mockIdentity(), $this->mockPrincipal());

        self::assertSame([Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class], self::classes($events));
    }

    /**
     * A trusted bind of a principal whose tenant cannot be loaded reports no
     * tenant rather than failing the bind.
     *
     * @return void
     */
    public function testATenantThatCannotBeLoadedIsReportedAsNone(): void
    {
        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')->andThrow(new TenantUnavailableException('gone'));

        $events = $this->recordEvents();

        $this->makeGuard()->authenticateAs($this->mockIdentity(), $principal);

        $assigned = $events->getArrayCopy()[1];

        self::assertInstanceOf(PrincipalAssigned::class, $assigned);
        self::assertNull($assigned->context->tenant);
        self::assertNull($assigned->context->tenantId);
    }

    /**
     * A principal loaded without its tenant's key is a misconfiguration, and
     * its `LogicException` propagates from a trusted bind instead of being
     * reported as no tenant.
     *
     * @return void
     */
    public function testAMisconfiguredTenantPropagatesFromATrustedBind(): void
    {
        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')->andThrow(new \LogicException('tenant key not loaded'));

        $this->recordEvents();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('tenant key not loaded');

        $this->makeGuard()->authenticateAs($this->mockIdentity(), $principal);
    }

    /**
     * `setPrincipal()` and `setDevice()` report the context bound with them:
     * the device's method once a device is bound, and the tenant of the bound
     * principal.
     *
     * @return void
     */
    public function testTheSettersReportTheContextBoundWithThem(): void
    {
        $identity = $this->mockIdentity();
        $device   = $this->mockDevice();
        $device->shouldReceive('getSignInMethod')->andReturn('passkey');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($identity, $this->mockPrincipal());

        $principal = $this->mockPrincipal();

        $guard->setDevice($device);
        $guard->setPrincipal($principal);

        $recorded = $events->getArrayCopy();
        $bound    = $recorded[2];
        $assigned = $recorded[3];

        self::assertInstanceOf(DeviceAuthenticated::class, $bound);
        self::assertSame($identity, $bound->context->identity);
        self::assertSame($device, $bound->context->device);
        self::assertSame('passkey', $bound->context->method);
        self::assertInstanceOf(PrincipalAssigned::class, $assigned);
        self::assertSame($principal, $assigned->context->principal);
        self::assertSame($device, $assigned->context->device);
        self::assertSame('passkey', $assigned->context->method);
    }

    /**
     * A device set on a guard with no principal bound reports no tenant.
     *
     * @return void
     */
    public function testADeviceSetWithoutAPrincipalReportsNoTenant(): void
    {
        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $this->provider->shouldNotReceive('retrieveById');

        $guard->setDevice($this->mockDevice());

        $bound = $events->getArrayCopy()[0];

        self::assertInstanceOf(DeviceAuthenticated::class, $bound);
        self::assertInstanceOf(EventContext::class, $bound->context);
        self::assertNull($bound->context->principal);
        self::assertNull($bound->context->tenant);
    }

    /**
     * Record every event the guard dispatches.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, object> $events */
        $events = new \ArrayObject;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use ($events): void {
                $events->append($event);
            });

        return $events;
    }

    /**
     * The classes of the recorded events, in order.
     *
     * @param  \ArrayObject<int, object>  $events
     * @return list<string>
     */
    private static function classes(\ArrayObject $events): array
    {
        return array_values(array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));
    }
}
