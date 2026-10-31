<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use Tests\Unit\Stubs\StubCredentialGuard;

/**
 * Feature tests for the protected hooks `AbstractGuard` offers to subclasses
 * that implement a new guard type.
 *
 * Drives `bindAuthenticationLifecycle()`, `setIdentity()`,
 * `fireValidatedEvent()`, `resolvePrincipal()`, and the guard context's timebox
 * budget from a subclass so the extension surface stays callable and behaves as
 * documented.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardExtensionTest extends AbstractGuardTestCase
{
    /**
     * A subclass binding a resolved context fires `Login`, `Authenticated`,
     * `PrincipalAssigned`, and `DeviceAuthenticated` in order and leaves the
     * full context bound.
     *
     * @return void
     */
    public function testSubclassBindsAuthenticationLifecycle(): void
    {
        $guard     = $this->makeCredentialGuard();
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();
        $device    = $this->mockDevice();

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        $guard->bindResolvedContext($identity, $principal, $device);

        self::assertSame(
            [Login::class, Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class],
            $dispatched,
        );
        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertSame($device, $guard->device());
    }

    /**
     * A subclass binding an identity directly fires `Authenticated` and leaves
     * the identity bound.
     *
     * @return void
     */
    public function testSubclassBindsIdentity(): void
    {
        $guard    = $this->makeCredentialGuard();
        $identity = $this->mockIdentity();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (object $event): bool => $event instanceof Authenticated
                && $event->guard === self::GUARD_NAME
                && $event->user  === $identity));

        $guard->bindIdentity($identity);

        self::assertSame($identity, $guard->user());
    }

    /**
     * A subclass that validated a user out-of-band can fire `Validated` for it.
     *
     * @return void
     */
    public function testSubclassFiresValidatedEvent(): void
    {
        $guard    = $this->makeCredentialGuard();
        $identity = $this->mockIdentity();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (object $event): bool => $event instanceof Validated
                && $event->guard === self::GUARD_NAME
                && $event->user  === $identity));

        $guard->announceValidated($identity);
    }

    /**
     * A subclass resolves an identity's principal through the guard's resolver:
     * its default principal without a hint, the hinted one with.
     *
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function testSubclassResolvesPrincipalsThroughTheResolver(): void
    {
        $identity = $this->mockIdentity();
        $default  = $this->mockPrincipal();
        $hinted   = $this->mockPrincipal();

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($default);
        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'membership-2')->andReturn($hinted);

        $guard = $this->makeCredentialGuard();

        self::assertSame($default, $guard->principalFor($identity));
        self::assertSame($hinted, $guard->principalFor($identity, 'membership-2'));
    }

    /**
     * A subclass reads the configured credential timebox budget.
     *
     * @return void
     */
    public function testSubclassReadsConfiguredTimeboxBudget(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 123456);

        self::assertSame(123456, $this->makeCredentialGuard()->credentialTimeboxMicroseconds());
    }

    /**
     * Instantiate the credential-path stub guard with the current set of
     * collaborator mocks.
     *
     * @return \Tests\Unit\Stubs\StubCredentialGuard
     */
    private function makeCredentialGuard(): StubCredentialGuard
    {
        return new StubCredentialGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);
    }
}
