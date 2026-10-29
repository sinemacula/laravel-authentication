<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;

/**
 * Feature tests proving every contextual accessor resolves the request on first
 * access, through the guard's `user()`, rather than reading state that only an
 * earlier `user()` call would have bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(BindsContextualState::class)]
final class BindsContextualStateTest extends AbstractGuardTestCase
{
    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity Identity the guard resolves. */
    private MockInterface $identity;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal Principal the guard resolves. */
    private MockInterface $principal;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Device Device the guard resolves. */
    private MockInterface $device;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasType&\SineMacula\Laravel\Authentication\Contracts\Tenant Tenant the principal acts within. */
    private MockInterface $tenant;

    /**
     * Build the context a resolving guard binds on first access.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->identity  = $this->mockIdentity();
        $this->principal = $this->mockPrincipal();
        $this->device    = $this->mockDevice();
        $this->tenant    = \Mockery::mock(HasType::class, Tenant::class);

        $this->principal->shouldReceive('getTenant')->andReturn($this->tenant);
        $this->tenant->shouldReceive('getType')->andReturn('staff');
        $this->tenant->shouldReceive('getTenantIdentifier')->andReturn('tenant-1');

        $this->events->shouldReceive('dispatch');
    }

    /**
     * The first call to `identity()` resolves the request.
     *
     * @return void
     */
    public function testIdentityResolvesTheRequestOnFirstCall(): void
    {
        self::assertSame($this->identity, $this->makeResolvingGuard()->identity());
    }

    /**
     * The first call to `principal()` resolves the request before reading the
     * bound principal.
     *
     * @return void
     */
    public function testPrincipalResolvesTheRequestOnFirstCall(): void
    {
        self::assertSame($this->principal, $this->makeResolvingGuard()->principal());
    }

    /**
     * The first call to `device()` resolves the request before reading the
     * bound device.
     *
     * @return void
     */
    public function testDeviceResolvesTheRequestOnFirstCall(): void
    {
        self::assertSame($this->device, $this->makeResolvingGuard()->device());
    }

    /**
     * The first call to `tenant()` resolves the request through `principal()`.
     *
     * @return void
     */
    public function testTenantResolvesTheRequestOnFirstCall(): void
    {
        self::assertSame($this->tenant, $this->makeResolvingGuard()->tenant());
    }

    /**
     * `tenant()` and `type()` return `null` when the request resolves no
     * principal.
     *
     * @return void
     */
    public function testTenantAndTypeReturnNullWhenNoPrincipalResolves(): void
    {
        $guard = $this->makeGuard();

        self::assertNull($guard->tenant());
        self::assertNull($guard->type());
    }

    /**
     * The first call to `id()` resolves the request through `user()`.
     *
     * @return void
     */
    public function testIdResolvesTheRequestOnFirstCall(): void
    {
        $this->identity->shouldReceive('getAuthIdentifier')->andReturn(42);

        self::assertSame(42, $this->makeResolvingGuard()->id());
    }

    /**
     * The first call to `type()` resolves the request through `principal()`
     * and, the principal declaring no type, reads its tenant's.
     *
     * @return void
     */
    public function testTypeResolvesTheRequestOnFirstCall(): void
    {
        self::assertSame('staff', $this->makeResolvingGuard()->type());
    }

    /**
     * A principal pinned before anything resolved the request is pinned over
     * the principal the request binds, not replaced by it on the next access.
     *
     * @return void
     */
    public function testSetPrincipalBeforeFirstAccessPinsOverTheResolvedPrincipal(): void
    {
        $pinned = $this->mockPrincipal();
        $guard  = $this->makeResolvingGuard();

        $guard->setPrincipal($pinned);

        self::assertSame($pinned, $guard->principal());
        self::assertSame($this->identity, $guard->identity());
        self::assertSame($this->device, $guard->device());
    }

    /**
     * A device pinned before anything resolved the request is pinned over the
     * device the request binds, not replaced by it on the next access.
     *
     * @return void
     */
    public function testSetDeviceBeforeFirstAccessPinsOverTheResolvedDevice(): void
    {
        $pinned = $this->mockDevice();
        $guard  = $this->makeResolvingGuard();

        $guard->setDevice($pinned);

        self::assertSame($pinned, $guard->device());
        self::assertSame($this->identity, $guard->identity());
        self::assertSame($this->principal, $guard->principal());
    }

    /**
     * `setPrincipal()` reports the context bound with it: the principal's
     * tenant, and the method of a device already bound, or none without one.
     *
     * @return void
     */
    public function testSetPrincipalReportsTheBoundContext(): void
    {
        $this->device->shouldReceive('getSignInMethod')->andReturn('password');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($this->identity, $this->principal, $this->device);
        $events->exchangeArray([]);

        $other = $this->mockPrincipal();

        $guard->setPrincipal($other);

        $first = $this->contextsOf($events, PrincipalAssigned::class);

        self::assertCount(1, $first);
        self::assertSame($other, $first[0]->principal);
        self::assertSame($this->device, $first[0]->device);
        self::assertSame('password', $first[0]->method);
    }

    /**
     * `setPrincipal()` with no device bound reports no method and no device.
     *
     * @return void
     */
    public function testSetPrincipalWithoutADeviceReportsNoMethod(): void
    {
        $events = $this->recordEvents();

        $this->makeGuard()->setPrincipal($this->principal);

        $contexts = $this->contextsOf($events, PrincipalAssigned::class);

        self::assertCount(1, $contexts);
        self::assertNull($contexts[0]->device);
        self::assertNull($contexts[0]->method);
        self::assertSame($this->tenant, $contexts[0]->tenant);
    }

    /**
     * `setDevice()` reports the tenant of the principal already bound, and no
     * tenant when no principal is bound.
     *
     * @return void
     */
    public function testSetDeviceReportsTheBoundPrincipalsTenant(): void
    {
        $this->device->shouldReceive('getSignInMethod')->andReturn('password');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->setDevice($this->device);

        $guard->authenticateAs($this->identity, $this->principal);
        $guard->setDevice($this->device);

        $contexts = $this->contextsOf($events, DeviceAuthenticated::class);

        self::assertCount(2, $contexts);
        self::assertNull($contexts[0]->tenant);
        self::assertNull($contexts[0]->principal);
        self::assertSame($this->tenant, $contexts[1]->tenant);
        self::assertSame('password', $contexts[1]->method);
    }

    /**
     * A principal whose tenant cannot be loaded is bound, and reported with no
     * tenant, rather than failing the bind.
     *
     * @return void
     */
    public function testATenantThatCannotBeLoadedIsBoundAsNone(): void
    {
        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')->andThrow(new TenantUnavailableException('The tenant is not available.'));

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($this->identity, $principal);

        self::assertNull($this->contextsOf($events, PrincipalAssigned::class)[0]->tenant);
        self::assertSame($principal, $guard->principal());
    }

    /**
     * A bind without a device dispatches no `DeviceAuthenticated`.
     *
     * @return void
     */
    public function testABindWithoutADeviceDispatchesNoDeviceEvent(): void
    {
        $events = $this->recordEvents();

        $this->makeGuard()->authenticateAs($this->identity, $this->principal);

        self::assertSame([], $this->contextsOf($events, DeviceAuthenticated::class));
        self::assertCount(1, $this->contextsOf($events, PrincipalAssigned::class));
    }

    /**
     * Build a guard whose `user()` binds the context on its first call, as a
     * request-resolving guard does.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function makeResolvingGuard(): AbstractGuard
    {
        $guard = new class (self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox) extends AbstractGuard {
            /** @var ?array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal, 2: \SineMacula\Laravel\Authentication\Contracts\Device} Context bound on the first `user()` call. */
            public ?array $pending = null;

            /**
             * Bind the pending context on the first call, then return it.
             *
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
             */
            #[\Override]
            public function user(): ?Identity
            {
                if ($this->pending !== null) {

                    $pending       = $this->pending;
                    $this->pending = null;

                    $this->login(...$pending);
                }

                return $this->identity;
            }
        };

        $guard->pending = [$this->identity, $this->principal, $this->device];

        return $guard;
    }

    /**
     * Record every event the guard dispatches.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordEvents(): \ArrayObject
    {
        $this->events = \Mockery::mock(Dispatcher::class);

        /** @var \ArrayObject<int, object> $events */
        $events = new \ArrayObject;

        $this->events->shouldReceive('dispatch')->andReturnUsing(static function (object $event) use ($events): void {
            $events->append($event);
        });

        return $events;
    }

    /**
     * The contexts of the recorded events of the class.
     *
     * @param  \ArrayObject<int, object>  $events
     * @param  class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>  $class
     * @return list<\SineMacula\Laravel\Authentication\Events\EventContext>
     */
    private function contextsOf(\ArrayObject $events, string $class): array
    {
        $contexts = [];

        foreach ($events as $event) {

            if (!$event instanceof $class) {
                continue;
            }

            $contexts[] = $event->context();
        }

        return $contexts;
    }
}
