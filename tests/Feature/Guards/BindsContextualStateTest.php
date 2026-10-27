<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
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

        $this->identity  = \Mockery::mock(Identity::class);
        $this->principal = \Mockery::mock(Principal::class);
        $this->device    = \Mockery::mock(Device::class);
        $this->tenant    = \Mockery::mock(HasType::class, Tenant::class);

        $this->principal->shouldReceive('getTenant')->andReturn($this->tenant);
        $this->tenant->shouldReceive('getType')->andReturn('staff');

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
     * The first call to `type()` resolves the request through `tenant()`.
     *
     * @return void
     */
    public function testTypeResolvesTheRequestOnFirstCall(): void
    {
        self::assertSame('staff', $this->makeResolvingGuard()->type());
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
                    $this->login(...$this->pending);
                    $this->pending = null;
                }

                return $this->identity;
            }
        };

        $guard->pending = [$this->identity, $this->principal, $this->device];

        return $guard;
    }
}
