<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Fixtures\Events\EventContextAssertions;

/**
 * Feature tests for the context every bind sets and reports in its events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversTrait(BindsContextualState::class)]
final class AbstractGuardEventContextTest extends AbstractGuardTestCase
{
    /**
     * `authenticateAs()` binds the triple and fires only the bind events, with
     * no `Validated` or `Login`.
     *
     * @return void
     */
    public function testAuthenticateAsReportsTheBindButNoSignIn(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $session   = $this->mockSession();
        $events    = $this->recordEvents();
        $guard     = $this->makeGuard();

        $guard->authenticateAs($identity, $principal, $session);

        self::assertSame([Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class], self::classes($events));
        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertSame($session, $guard->session());
    }

    /**
     * `authenticateAs()` replaces the prior bind and settles the request.
     *
     * @return void
     */
    public function testAuthenticateAsReplacesThePriorBindAndSettlesTheRequest(): void
    {
        $this->recordEvents();

        $guard = $this->makeGuard();

        $guard->login($this->mockIdentity(), $this->mockPrincipal(), $this->mockSession());

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();

        $guard->authenticateAs($identity, $principal);

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertNull($guard->session());
    }

    /**
     * Every bind sets the whole triple before its first event.
     *
     * @return void
     */
    public function testAListenerOnAuthenticatedSeesTheWholeContext(): void
    {
        $guard     = $this->makeGuard();
        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $session   = $this->mockSession();
        $seen      = null;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use ($guard, &$seen): void {
                if (!$event instanceof Authenticated) {
                    return;
                }

                $seen = [$guard->principal(), $guard->session()];
            });

        $guard->login($identity, $principal, $session);

        self::assertSame([$principal, $session], $seen);
    }

    /**
     * `PrincipalAssigned` and `SessionAuthenticated` of one bind carry the
     * same, whole context.
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
        $session   = $this->mockSession();

        $principal->shouldReceive('getTenant')->andReturn($tenant);
        $session->shouldReceive('getSignInMethod')->andReturn('password');
        $session->shouldReceive('getTenantId')->andReturn('5');

        $events = $this->recordEvents();

        $this->makeGuard()->login($identity, $principal, $session);

        [, , , $assigned, $authenticated] = $events->getArrayCopy();

        self::assertInstanceOf(PrincipalAssigned::class, $assigned);
        self::assertInstanceOf(SessionAuthenticated::class, $authenticated);
        self::assertSame($assigned->context, $authenticated->context);

        $context = $assigned->context;

        self::assertSame(self::GUARD_NAME, $context->guard);
        self::assertSame('203.0.113.9', $context->client->ip);
        self::assertSame('Agent/1.0', $context->client->userAgent);
        EventContextAssertions::assertIdentity($identity, $context);
        EventContextAssertions::assertPrincipal($principal, $context);
        EventContextAssertions::assertTenant($tenant, $context);
        self::assertSame('5', $context->tenantId);
        EventContextAssertions::assertSession($session, $context);
        self::assertSame('password', $context->method);
    }

    /**
     * `login()` reports a sign-in: `Validated` and `Login` come before the bind
     * events, and `SignedIn` after them.
     *
     * @return void
     */
    public function testLoginReportsTheSignInAroundTheBind(): void
    {
        $events = $this->recordEvents();

        $this->makeGuard()->login($this->mockIdentity(), $this->mockPrincipal());

        self::assertSame([Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, SignedIn::class], self::classes($events));
    }

    /**
     * `login()` reports its sign-in with the context the bind reports, the
     * client given and the method the session records.
     *
     * @return void
     */
    public function testLoginReportsTheSignInWithTheBoundContext(): void
    {
        $tenant = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn(5);

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $session   = $this->mockSession();

        $principal->shouldReceive('getTenant')->andReturn($tenant);
        $session->shouldReceive('getSignInMethod')->andReturn('passkey');
        $session->shouldReceive('getTenantId')->andReturn('5');

        $events = $this->recordEvents();

        $client = new ClientContext('198.51.100.4', 'Worker/3.1');

        $this->makeGuard()->login($identity, $principal, $session, $client);

        $signedIn = $events->getArrayCopy()[5];

        self::assertInstanceOf(SignedIn::class, $signedIn);
        self::assertFalse($signedIn->refresh);
        self::assertSame(self::GUARD_NAME, $signedIn->context->guard);
        self::assertSame($client, $signedIn->context->client);
        EventContextAssertions::assertIdentity($identity, $signedIn->context);
        EventContextAssertions::assertPrincipal($principal, $signedIn->context);
        EventContextAssertions::assertTenant($tenant, $signedIn->context);
        EventContextAssertions::assertSession($session, $signedIn->context);
        self::assertSame('passkey', $signedIn->context->method);
    }

    /**
     * `loginStarted()` binds the session service's sign-in without reporting it
     * again.
     *
     * @return void
     */
    public function testLoginStartedLeavesTheSignInToTheFlowThatStartedIt(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $session   = $this->mockSession();
        $events    = $this->recordEvents();
        $guard     = $this->makeGuard();

        $guard->loginStarted($identity, $principal, $session);

        self::assertSame([Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class], self::classes($events));
        self::assertSame([$identity, $principal, $session], [$guard->user(), $guard->principal(), $guard->session()]);
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
        EventContextAssertions::assertTenant(null, $assigned->context);
        self::assertNull($assigned->context->tenantId);
    }

    /**
     * A principal loaded without its tenant's key throws its `LogicException`
     * from a trusted bind.
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
     * `setPrincipal()` and `setSession()` report the session's method and the
     * bound principal's tenant.
     *
     * @return void
     */
    public function testTheSettersReportTheContextBoundWithThem(): void
    {
        $identity = $this->mockIdentity();
        $session  = $this->mockSession();
        $session->shouldReceive('getSignInMethod')->andReturn('passkey');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($identity, $this->mockPrincipal());

        $principal = $this->mockPrincipal();

        $guard->setSession($session);
        $guard->setPrincipal($principal);

        $recorded = $events->getArrayCopy();
        $bound    = $recorded[2];
        $assigned = $recorded[3];

        self::assertInstanceOf(SessionAuthenticated::class, $bound);
        EventContextAssertions::assertIdentity($identity, $bound->context);
        EventContextAssertions::assertSession($session, $bound->context);
        self::assertSame('passkey', $bound->context->method);
        self::assertInstanceOf(PrincipalAssigned::class, $assigned);
        EventContextAssertions::assertPrincipal($principal, $assigned->context);
        EventContextAssertions::assertSession($session, $assigned->context);
        self::assertSame('passkey', $assigned->context->method);
    }

    /**
     * A session set on a guard with no principal bound reports no tenant.
     *
     * @return void
     */
    public function testASessionSetWithoutAPrincipalReportsNoTenant(): void
    {
        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $this->provider->shouldNotReceive('retrieveById');

        $guard->setSession($this->mockSession());

        $bound = $events->getArrayCopy()[0];

        self::assertInstanceOf(SessionAuthenticated::class, $bound);
        self::assertInstanceOf(EventContext::class, $bound->context);
        EventContextAssertions::assertPrincipal(null, $bound->context);
        EventContextAssertions::assertTenant(null, $bound->context);
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
