<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Feature tests for `AbstractGuard::setUser()`: it replaces the whole
 * contextual state and binds the new identity's default principal, so one
 * identity is never paired with another's principal or device.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardSetUserTest extends AbstractGuardTestCase
{
    /**
     * Ignore dispatched events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->events->shouldReceive('dispatch');
    }

    /**
     * `setUser(A)` then `setUser(B)` binds each identity with its own default
     * principal.
     *
     * @return void
     */
    public function testSetUserTwiceBindsEachIdentitysOwnPrincipal(): void
    {
        $guard = $this->makeGuard();

        $first           = $this->mockIdentity();
        $second          = $this->mockIdentity();
        $firstPrincipal  = $this->mockPrincipal();
        $secondPrincipal = $this->mockPrincipal();

        $this->resolver->shouldReceive('resolve')->once()->with($first)->andReturn($firstPrincipal);
        $this->resolver->shouldReceive('resolve')->once()->with($second)->andReturn($secondPrincipal);

        $guard->setUser($first);

        self::assertSame($first, $guard->identity());
        self::assertSame($firstPrincipal, $guard->principal());

        $guard->setUser($second);

        self::assertSame($second, $guard->identity());
        self::assertSame($secondPrincipal, $guard->principal());
    }

    /**
     * `setUser()` after a `login()` with a device clears that device and the
     * previous principal.
     *
     * @return void
     */
    public function testSetUserClearsThePreviousIdentitysPrincipalAndDevice(): void
    {
        $guard = $this->makeGuard();

        $guard->login($this->mockIdentity(), $this->mockPrincipal(), $this->mockDevice());

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($principal);

        $guard->setUser($identity);

        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertNull($guard->device());
    }

    /**
     * An identity with no default principal fails clearly, and the guard keeps
     * what it had bound.
     *
     * @return void
     */
    public function testSetUserThrowsWhenNoDefaultPrincipalResolves(): void
    {
        $guard = $this->makeGuard();

        $bound          = $this->mockIdentity();
        $boundPrincipal = $this->mockPrincipal();

        $guard->login($bound, $boundPrincipal);

        $identity = $this->mockIdentity();

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturnNull();

        try {
            $guard->setUser($identity);
            self::fail('Expected setUser() to reject an identity without a default principal.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(
                sprintf('Guard %s could not resolve a default principal for identity %s; bind one with login().', self::GUARD_NAME, $identity::class),
                $exception->getMessage(),
            );
        }

        self::assertSame($bound, $guard->identity());
        self::assertSame($boundPrincipal, $guard->principal());
    }

    /**
     * A misconfigured identity propagates the resolver's
     * `UnresolvableIdentityException`.
     *
     * @return void
     */
    public function testSetUserPropagatesUnresolvableIdentityException(): void
    {
        $guard = $this->makeGuard();

        $identity = $this->mockIdentity();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andThrow(new UnresolvableIdentityException('cannot resolve'));

        $this->expectException(UnresolvableIdentityException::class);

        $guard->setUser($identity);
    }
}
