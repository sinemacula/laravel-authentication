<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use Tests\Unit\Stubs\StubRequestResolvingGuard;

/**
 * Feature tests for request resolution on `AbstractGuard`: `user()` resolves
 * the request at most once, success or failure, `setRequest()` starts over,
 * explicit sign-in still works after a failed resolution, and `logout()` keeps
 * the guard signed out for the rest of the request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardRequestResolutionTest extends AbstractGuardTestCase
{
    /**
     * Record dispatched events without asserting on them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->events->shouldReceive('dispatch')->byDefault();
    }

    /**
     * A failed resolution is attempted once: later `user()`, `check()` and
     * `id()` calls on the same request do not resolve again.
     *
     * @return void
     */
    public function testFailedResolutionIsAttemptedOncePerRequest(): void
    {
        $guard = $this->makeResolvingGuard(null);

        self::assertNull($guard->user());
        self::assertNull($guard->user());
        self::assertFalse($guard->check());
        self::assertNull($guard->id());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * A successful resolution is not repeated either.
     *
     * @return void
     */
    public function testSuccessfulResolutionIsAttemptedOncePerRequest(): void
    {
        $identity = $this->mockIdentity();
        $guard    = $this->makeResolvingGuard($identity);

        self::assertSame($identity, $guard->user());
        self::assertSame($identity, $guard->user());
        self::assertTrue($guard->check());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * `setRequest()` forgets the failed attempt, so the next request resolves
     * again.
     *
     * @return void
     */
    public function testSetRequestStartsResolutionOverForTheNextRequest(): void
    {
        $guard = $this->makeResolvingGuard(null);

        self::assertNull($guard->user());

        $identity          = $this->mockIdentity();
        $guard->resolvable = $identity;

        $guard->setRequest(Request::create('/next', 'GET'));

        self::assertSame($identity, $guard->user());
        self::assertSame(2, $guard->resolutions);
    }

    /**
     * An explicit `login()` after a failed resolution binds the identity.
     *
     * @return void
     */
    public function testLoginAfterFailedResolutionBindsTheIdentity(): void
    {
        $guard = $this->makeResolvingGuard(null);

        self::assertNull($guard->user());

        $identity = $this->mockIdentity();

        $guard->login($identity, \Mockery::mock(Principal::class));

        self::assertSame($identity, $guard->user());
        self::assertTrue($guard->check());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * An explicit `setUser()` after a failed resolution binds the identity.
     *
     * @return void
     */
    public function testSetUserAfterFailedResolutionBindsTheIdentity(): void
    {
        $guard = $this->makeResolvingGuard(null);

        self::assertNull($guard->user());

        $identity = $this->mockIdentity();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn(\Mockery::mock(Principal::class));

        $guard->setUser($identity);

        self::assertSame($identity, $guard->user());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * After `logout()` the guard stays signed out for the rest of the request,
     * even though the request still carries a credential that would resolve.
     *
     * @return void
     */
    public function testLogoutKeepsTheGuardSignedOutForTheRestOfTheRequest(): void
    {
        $identity = $this->mockIdentity();
        $guard    = $this->makeResolvingGuard($identity);

        self::assertSame($identity, $guard->user());

        $guard->logout();

        self::assertNull($guard->user());
        self::assertFalse($guard->check());
        self::assertNull($guard->identity());
        self::assertNull($guard->principal());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * An explicit `login()` settles the request before it fires `Login`: a
     * listener that reads the guard mid-bind gets no identity instead of
     * resolving the request's own credential, and the guard ends up bound to
     * the identity signing in.
     *
     * @return void
     */
    public function testLoginSettlesTheRequestBeforeListenersReadTheGuard(): void
    {
        $guard = $this->makeResolvingGuard($this->mockIdentity());
        $seen  = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use ($guard, &$seen): void {

                if (!$event instanceof Login) {
                    return;
                }

                $seen[] = $guard->id();
            });

        $identity = $this->mockIdentity();

        $guard->login($identity, \Mockery::mock(Principal::class));

        self::assertSame([null], $seen);
        self::assertSame(0, $guard->resolutions);
        self::assertSame($identity, $guard->user());
    }

    /**
     * After an explicit `login()` and `logout()`, the request's own credential
     * is not resolved either: the guard stays signed out.
     *
     * @return void
     */
    public function testLogoutAfterExplicitLoginKeepsTheGuardSignedOut(): void
    {
        $guard = $this->makeResolvingGuard($this->mockIdentity());

        $guard->login($this->mockIdentity(), \Mockery::mock(Principal::class));
        $guard->logout();

        self::assertNull($guard->user());
        self::assertSame(0, $guard->resolutions);
    }

    /**
     * `logout()` on a request nothing has resolved yet resolves it first, so
     * `Logout` carries the request's identity, and the guard then stays signed
     * out.
     *
     * @return void
     */
    public function testLogoutResolvesTheRequestBeforeSigningOut(): void
    {
        $identity = $this->mockIdentity();
        $guard    = $this->makeResolvingGuard($identity);

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof Logout
                    && $event->user === $identity),
            );

        $guard->logout();

        self::assertNull($guard->user());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * An explicit sign-in after `logout()` binds again.
     *
     * @return void
     */
    public function testLoginAfterLogoutSignsInAgain(): void
    {
        $guard = $this->makeResolvingGuard($this->mockIdentity());

        $guard->logout();

        $identity = $this->mockIdentity();

        $guard->login($identity, \Mockery::mock(Principal::class));

        self::assertSame($identity, $guard->user());
    }

    /**
     * `setUser()` after `logout()` binds again.
     *
     * @return void
     */
    public function testSetUserAfterLogoutSignsInAgain(): void
    {
        $guard = $this->makeResolvingGuard($this->mockIdentity());

        $guard->logout();

        $identity = $this->mockIdentity();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn(\Mockery::mock(Principal::class));

        $guard->setUser($identity);

        self::assertSame($identity, $guard->user());
    }

    /**
     * A new request after `logout()` resolves its own credential.
     *
     * @return void
     */
    public function testSetRequestAfterLogoutResolvesTheNextRequest(): void
    {
        $identity = $this->mockIdentity();
        $guard    = $this->makeResolvingGuard($identity);

        $guard->logout();
        $guard->setRequest(Request::create('/next', 'GET'));

        self::assertSame($identity, $guard->user());
        self::assertSame(2, $guard->resolutions);
    }

    /**
     * A listener that calls `user()` while the request is being resolved gets
     * `null` instead of re-entering resolution.
     *
     * @return void
     */
    public function testResolutionIsNotReenteredFromWithinResolution(): void
    {
        $guard          = $this->makeResolvingGuard(null);
        $guard->reenter = true;

        self::assertNull($guard->user());
        self::assertSame(1, $guard->resolutions);
        self::assertSame([null], $guard->reentered);
    }

    /**
     * The base guard reads no request credential.
     *
     * @return void
     */
    public function testBaseGuardResolvesNoIdentityFromTheRequest(): void
    {
        self::assertNull($this->makeGuard()->user());
    }

    /**
     * Build a guard whose request resolution counts its calls and binds the
     * configured identity.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \Tests\Unit\Stubs\StubRequestResolvingGuard
     */
    private function makeResolvingGuard(?Identity $identity): StubRequestResolvingGuard
    {
        $guard = new StubRequestResolvingGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);

        $guard->resolvable = $identity;

        return $guard;
    }
}
