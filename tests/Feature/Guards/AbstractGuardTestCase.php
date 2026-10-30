<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Timebox;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use Tests\Concerns\BindsSignInPolicyDoubles;
use Tests\Unit\Stubs\StubDevice;

/**
 * Shared base case for the AbstractGuard split tests.
 *
 * Owns the collaborator mocks (provider, resolver, dispatcher, request,
 * timebox), the Testbench environment definition, and the `makeGuard()` factory
 * used by every concrete `AbstractGuardTest` variant. Subclasses focus on a
 * single behavioural slice of AbstractGuard so each class stays focused on a
 * single concern.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class AbstractGuardTestCase extends TestCase
{
    use BindsSignInPolicyDoubles, MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to the concrete test double. */
    protected const string GUARD_NAME = 'test-guard';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    protected MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    protected MockInterface $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher&\Mockery\MockInterface The mocked event dispatcher collaborator. */
    protected MockInterface $events;

    /** @var \Illuminate\Http\Request&\Mockery\MockInterface The mocked HTTP request collaborator. */
    protected MockInterface $request;

    /** @var \Illuminate\Support\Timebox&\Mockery\MockInterface The mocked timebox collaborator. */
    protected MockInterface $timebox;

    /**
     * Build fresh collaborator mocks before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        assert($this->app !== null);

        self::bindSignInPolicyDoubles($this->app, new TokenLifetimes(15, 60 * 24 * 30, 60 * 24 * 180, 30));

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->events   = \Mockery::mock(Dispatcher::class);
        $this->request  = \Mockery::mock(Request::class);
        $this->timebox  = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->andReturnSelf();

        // attempt() rehashes a password once it is accepted.
        $this->provider->shouldReceive('rehashPasswordIfRequired')
            ->byDefault();

        $this->request->shouldReceive('ip')
            ->byDefault()
            ->andReturnNull();
        $this->request->shouldReceive('userAgent')
            ->byDefault()
            ->andReturnNull();

        // Default: Timebox::call() invokes the callback directly and returns
        // its result so tests exercise the real credential validation path.
        // Tests that need to assert the timebox budget override this
        // expectation.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));
    }

    /**
     * Instantiate a concrete AbstractGuard subclass with the current set of
     * collaborator mocks. The anonymous subclass adds no behaviour beyond
     * forwarding its constructor arguments to the parent.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    protected function makeGuard(): AbstractGuard
    {
        return new class (self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox) extends AbstractGuard {};
    }

    /**
     * Build a Mockery mock of the Identity contract, with any further
     * capabilities, whose auth identifier (by which a checked password is
     * counted against the account) is 1 unless a test says otherwise.
     *
     * @param  class-string  ...$capabilities
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    protected function mockIdentity(string ...$capabilities): MockInterface
    {
        $identity = \Mockery::mock(Identity::class, ...$capabilities);
        $identity->shouldReceive('getAuthIdentifier')
            ->byDefault()
            ->andReturn(1);

        return $identity;
    }

    /**
     * Build a Mockery mock of the Principal contract, with any further
     * capabilities, whose identifier (which the events snapshot) is
     * `principal-1` and which acts within no tenant, unless a test says
     * otherwise.
     *
     * @param  class-string  ...$capabilities
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    protected function mockPrincipal(string ...$capabilities): MockInterface
    {
        $principal = \Mockery::mock(Principal::class, ...$capabilities);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->byDefault()
            ->andReturn('principal-1');
        $principal->shouldReceive('getTenant')
            ->byDefault()
            ->andReturnNull();

        return $principal;
    }

    /**
     * Build a Mockery mock of the Device contract whose identifier is
     * `device-1` and whose session records no sign-in method, unless a test
     * says otherwise.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Device
     */
    protected function mockDevice(): MockInterface
    {
        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')
            ->byDefault()
            ->andReturn('device-1');
        $device->shouldReceive('getSignInMethod')
            ->byDefault()
            ->andReturnNull();

        return $device;
    }

    /**
     * A live device of the guard, as a stored row would load, whose session
     * acts as the principal (so it can be pinned for it).
     *
     * @param  string  $id
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \Tests\Unit\Stubs\StubDevice
     */
    protected function pinnableDevice(string $id, Principal $principal): StubDevice
    {
        return new StubDevice([
            'id'                  => $id,
            'guard'               => self::GUARD_NAME,
            'sign_in_method'      => 'password',
            'principal_type'      => PrincipalReference::type($principal),
            'principal_id'        => PrincipalReference::id($principal),
            'revoked_at'          => null,
            'idle_expires_at'     => Carbon::now()->addDays(90),
            'absolute_expires_at' => Carbon::now()->addDays(180),
        ]);
    }

    /**
     * Build a Mockery mock of a `CanBeActive` principal whose `isActive()`
     * returns `true`, that acts within no tenant, and whose identifier (which
     * the events snapshot) is `principal-1` unless a test says otherwise - used
     * by any attempt-path test where the guard checks activation after the
     * resolver returns.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    protected function mockActivePrincipal(): MockInterface
    {
        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('isActive')
            ->byDefault()
            ->andReturnTrue();
        $principal->shouldReceive('getTenant')
            ->byDefault()
            ->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->byDefault()
            ->andReturn('principal-1');

        return $principal;
    }
}
