<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Events\Dispatcher;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\StubCredentialGuard;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubRequestResolvingGuard;

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

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Session Session the guard resolves. */
    private MockInterface $session;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant Tenant the principal acts within. */
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
        $this->session   = $this->mockSession();
        $this->tenant    = \Mockery::mock(Tenant::class);

        $this->principal->shouldReceive('getTenant')->andReturn($this->tenant);
        $this->tenant->shouldReceive('getTenantIdentifier')->andReturn('tenant-1');
        $this->session->shouldReceive('getTenantId')->andReturn('tenant-1');

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
     * The first call to `session()` resolves the request before reading the
     * bound session.
     *
     * @return void
     */
    public function testSessionResolvesTheRequestOnFirstCall(): void
    {
        self::assertSame($this->session, $this->makeResolvingGuard()->session());
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
     * `tenant()` returns `null` when the request resolves no principal.
     *
     * @return void
     */
    public function testTenantReturnsNullWhenNoPrincipalResolves(): void
    {
        self::assertNull($this->makeGuard()->tenant());
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
        self::assertSame($this->session, $guard->session());
    }

    /**
     * A session pinned before anything resolved the request is pinned over the
     * session the request binds, not replaced by it on the next access.
     *
     * @return void
     */
    public function testSetSessionBeforeFirstAccessPinsOverTheResolvedSession(): void
    {
        $pinned = $this->mockSession();
        $guard  = $this->makeResolvingGuard();

        $guard->setSession($pinned);

        self::assertSame($pinned, $guard->session());
        self::assertSame($this->identity, $guard->identity());
        self::assertSame($this->principal, $guard->principal());
    }

    /**
     * `setPrincipal()` reports the context bound with it: the principal's
     * tenant, and the method of a session already bound, or none without one.
     *
     * @return void
     */
    public function testSetPrincipalReportsTheBoundContext(): void
    {
        $this->session->shouldReceive('getSignInMethod')->andReturn('password');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($this->identity, $this->principal, $this->session);
        $events->exchangeArray([]);

        $other = $this->mockPrincipal();

        $guard->setPrincipal($other);

        $first = $this->contextsOf($events, PrincipalAssigned::class);

        self::assertCount(1, $first);
        EventContextAssertions::assertPrincipal($other, $first[0]);
        EventContextAssertions::assertSession($this->session, $first[0]);
        self::assertSame('password', $first[0]->method);
    }

    /**
     * `setPrincipal()` with no session bound reports no method and no session.
     *
     * @return void
     */
    public function testSetPrincipalWithoutASessionReportsNoMethod(): void
    {
        $events = $this->recordEvents();

        $this->makeGuard()->setPrincipal($this->principal);

        $contexts = $this->contextsOf($events, PrincipalAssigned::class);

        self::assertCount(1, $contexts);
        EventContextAssertions::assertSession(null, $contexts[0]);
        self::assertNull($contexts[0]->method);
        EventContextAssertions::assertTenant($this->tenant, $contexts[0]);
    }

    /**
     * `setSession()` reports the tenant of the principal already bound, and no
     * tenant when no principal is bound.
     *
     * @return void
     */
    public function testSetSessionReportsTheBoundPrincipalsTenant(): void
    {
        $this->session->shouldReceive('getSignInMethod')->andReturn('password');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->setSession($this->session);

        $guard->authenticateAs($this->identity, $this->principal);
        $guard->setSession($this->session);

        $contexts = $this->contextsOf($events, SessionAuthenticated::class);

        self::assertCount(2, $contexts);
        EventContextAssertions::assertTenant(null, $contexts[0]);
        EventContextAssertions::assertPrincipal(null, $contexts[0]);
        EventContextAssertions::assertTenant($this->tenant, $contexts[1]);
        self::assertSame('password', $contexts[1]->method);
    }

    /**
     * A principal whose tenant cannot be loaded is bound, and reported with no
     * tenant, rather than failing the bind; `tenant()` then throws the reason
     * instead of answering as for a principal acting in no tenant, until the
     * guard is forgotten.
     *
     * @return void
     */
    public function testATenantThatCannotBeLoadedIsBoundAsNone(): void
    {
        $unavailable = new TenantUnavailableException('The tenant is not available.');

        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')->andThrow($unavailable);

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($this->identity, $principal);

        EventContextAssertions::assertTenant(null, $this->contextsOf($events, PrincipalAssigned::class)[0]);
        self::assertSame($principal, $guard->principal());
        self::assertSame($unavailable, self::unavailableTenantOf($guard));

        $guard->forgetUser();

        self::assertNull($guard->tenant());
    }

    /**
     * A bind the guard verified holds the tenant its admission found as the
     * active tenant, whatever tenant the principal belongs to, until the guard
     * is bound again or forgotten.
     *
     * @return void
     */
    public function testAVerifiedBindHoldsTheTenantItWasGiven(): void
    {
        $other = \Mockery::mock(Tenant::class);
        $other->shouldReceive('getTenantIdentifier')->andReturn('tenant-2');

        $guard = $this->makeGuard();

        $guard->loginVerified($this->identity, $this->principal, $this->session, $other, 'password');

        self::assertSame($other, $guard->tenant());

        $guard->forgetUser();

        self::assertNull($guard->tenant());
    }

    /**
     * A trusted bind of a session acts in the tenant the session records: the
     * principal's own when the identifiers match, and none when it records
     * none; a session acting in a tenant that no longer resolves (the shipped
     * resolver finds none) makes `tenant()` throw rather than answer none; a
     * trusted bind without a session acts in the principal's own.
     *
     * @return void
     */
    public function testATrustedBindActsInTheTenantTheSessionRecords(): void
    {
        $elsewhere = $this->mockSession();
        $elsewhere->shouldReceive('getTenantId')->andReturn('tenant-2');

        $guard = $this->makeGuard();

        $guard->login($this->identity, $this->principal, $this->session);

        self::assertSame($this->tenant, $guard->tenant());

        $guard->authenticateAs($this->identity, $this->principal, $elsewhere);

        self::assertStringContainsString('tenant-2', self::unavailableTenantOf($guard)->getMessage());

        $guard->authenticateAs($this->identity, $this->principal, $this->mockSession());

        self::assertNull($guard->tenant());

        $guard->authenticateAs($this->identity, $this->principal);

        self::assertSame($this->tenant, $guard->tenant());
    }

    /**
     * A trusted bind checks no activity: the inactive tenant a session records
     * is bound as the active tenant, as a principal's inactive tenant is
     * without a session.
     *
     * @return void
     */
    public function testATrustedBindKeepsAnInactiveTenant(): void
    {
        $inactive = \Mockery::mock(Tenant::class, CanBeActive::class);
        $inactive->shouldReceive('getTenantIdentifier')->andReturn('tenant-1');
        $inactive->shouldReceive('isActive')->andReturnFalse();

        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')->andReturn($inactive);

        $guard = $this->makeGuard();

        $guard->login($this->identity, $principal, $this->session);

        self::assertSame($inactive, $guard->tenant());

        $guard->authenticateAs($this->identity, $principal);

        self::assertSame($inactive, $guard->tenant());
    }

    /**
     * A session's tenant that names the principal's own when that cannot be
     * loaded makes `tenant()` throw the principal's own reason.
     *
     * @return void
     */
    public function testASessionsTenantThatCannotBeLoadedThrowsItsReason(): void
    {
        $unavailable = new TenantUnavailableException('The tenant is not available.');

        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')->andThrow($unavailable);

        $guard = $this->makeGuard();

        $guard->login($this->identity, $principal, $this->session);

        self::assertSame($unavailable, self::unavailableTenantOf($guard));
    }

    /**
     * A tenant given to `authenticateAs()` is bound as given, as a test acting
     * in a tenant binds it.
     *
     * @return void
     */
    public function testAuthenticateAsBindsTheTenantGiven(): void
    {
        $other = \Mockery::mock(Tenant::class);
        $other->shouldReceive('getTenantIdentifier')->andReturn('tenant-2');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($this->identity, $this->principal, $this->session, tenant: $other);

        self::assertSame($other, $guard->tenant());
        EventContextAssertions::assertTenant($other, $this->contextsOf($events, PrincipalAssigned::class)[0]);
    }

    /**
     * `setPrincipal()` and `setSession()` move the active tenant to the one the
     * bound session records for the principal bound, or the principal's own
     * without a session.
     *
     * @return void
     */
    public function testSetPrincipalAndSetSessionMoveTheActiveTenant(): void
    {
        $guard = $this->makeGuard();
        $other = \Mockery::mock(Tenant::class);
        $other->shouldReceive('getTenantIdentifier')->andReturn('tenant-2');

        $guard->loginVerified($this->identity, $this->principal, null, $other, 'password');
        $guard->setPrincipal($this->principal);

        self::assertSame($this->tenant, $guard->tenant());

        $elsewhere = $this->mockSession();
        $elsewhere->shouldReceive('getTenantId')->andReturn('tenant-2');

        $guard->setSession($elsewhere);

        self::unavailableTenantOf($guard);

        $guard->setSession($this->session);

        self::assertSame($this->tenant, $guard->tenant());
    }

    /**
     * A bind without a session dispatches no `SessionAuthenticated`.
     *
     * @return void
     */
    public function testABindWithoutASessionDispatchesNoSessionEvent(): void
    {
        $events = $this->recordEvents();

        $this->makeGuard()->authenticateAs($this->identity, $this->principal);

        self::assertSame([], $this->contextsOf($events, SessionAuthenticated::class));
        self::assertCount(1, $this->contextsOf($events, PrincipalAssigned::class));
    }

    /**
     * The first call to `scopes()` resolves the request: a machine identity the
     * request binds without a credential is limited to no scope.
     *
     * @return void
     */
    public function testScopesResolvesTheRequestOnFirstCall(): void
    {
        $this->identity = $this->mockIdentity(MachineIdentity::class);

        self::assertSame([], $this->makeResolvingGuard()->scopes());
    }

    /**
     * A human identity bound without a credential has no scope ceiling, and its
     * events carry no credential and no scopes.
     *
     * @return void
     */
    public function testAHumanIdentityHasNoScopeCeiling(): void
    {
        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->login($this->identity, $this->principal, $this->session);

        self::assertNull($guard->scopes());

        $context = $this->contextsOf($events, PrincipalAssigned::class)[0];

        self::assertNull($context->credentialId);
        self::assertNull($context->scopes);
    }

    /**
     * `authenticateAs()` limits a machine identity to the scopes it is given,
     * as a credential granting them would, and its events carry them; given
     * scopes for a human identity, which no credential limits, it binds nothing
     * and throws.
     *
     * @return void
     */
    public function testAuthenticateAsLimitsAMachineToTheScopesGiven(): void
    {
        $machine = $this->mockIdentity(MachineIdentity::class);
        $events  = $this->recordEvents();
        $guard   = $this->makeGuard();

        $guard->authenticateAs($machine, $this->principal, null, ['reports:read']);

        self::assertSame(['reports:read'], $guard->scopes());
        self::assertSame(['reports:read'], $this->contextsOf($events, PrincipalAssigned::class)[0]->scopes);

        try {
            $guard->authenticateAs($this->identity, $this->principal, null, []);
            self::fail('A human was bound with scopes.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Scopes limit the credential of a machine identity; ', $exception->getMessage());
        }

        self::assertSame($machine, $guard->identity());
    }

    /**
     * A machine identity bound through any trusted bind, with no credential, is
     * limited to no scope: a trusted bind never gives a machine access without
     * a ceiling.
     *
     * @return void
     */
    public function testATrustedBindLimitsAMachineToNoScope(): void
    {
        $machine   = $this->mockIdentity(MachineIdentity::class);
        $principal = $this->principal;

        $this->resolver->shouldReceive('resolve')->with($machine)->andReturn($principal);

        $events = $this->recordEvents();

        $binds = [
            'login'          => static fn (AbstractGuard $guard) => $guard->login($machine, $principal),
            'setUser'        => static fn (AbstractGuard $guard) => $guard->setUser($machine),
            'authenticateAs' => static fn (AbstractGuard $guard) => $guard->authenticateAs($machine, $principal),
        ];

        foreach ($binds as $name => $bind) {

            $guard = $this->makeGuard();

            $bind($guard);

            self::assertSame([], $guard->scopes(), $name);
            self::assertSame([], $this->contextsOf($events, PrincipalAssigned::class)[0]->scopes, $name);

            $events->exchangeArray([]);
        }
    }

    /**
     * A context a credential authenticated is limited to the scopes it grants,
     * and every event describing it, a later principal or session bind's
     * included, carries the credential and its scopes; clearing the state,
     * signing out or forgetting the user clears them.
     *
     * @return void
     */
    public function testACredentialsScopesAreBoundAndReported(): void
    {
        $machine = $this->mockIdentity(MachineIdentity::class);
        $events  = $this->recordEvents();
        $guard   = new StubCredentialGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);

        $guard->bindCredential($machine, $this->principal, 'key-1', ['invoices:read']);

        self::assertSame(['invoices:read'], $guard->scopes());

        $guard->setPrincipal($this->principal);
        $guard->setSession($this->session);

        $contexts = [...$this->contextsOf($events, PrincipalAssigned::class), ...$this->contextsOf($events, SessionAuthenticated::class)];

        self::assertCount(3, $contexts);

        foreach ($contexts as $context) {
            self::assertSame('key-1', $context->credentialId);
            self::assertSame(['invoices:read'], $context->scopes);
        }

        $guard->clearState();

        self::assertNull($guard->scopes());

        $guard->bindCredential($machine, $this->principal, 'key-1', ['invoices:read']);
        $guard->logout();

        self::assertNull($guard->scopes());

        $guard->bindCredential($machine, $this->principal, 'key-2', []);

        self::assertSame([], $guard->scopes());

        $guard->forgetUser();

        self::assertNull($guard->scopes());

        $events->exchangeArray([]);

        $guard->setPrincipal($this->principal);

        self::assertNull($this->contextsOf($events, PrincipalAssigned::class)[0]->credentialId);
    }

    /**
     * `loginVerified()` binds as a sign-in, `Validated` and then `Login` before
     * the bind events, which carry the tenant and the method it is given rather
     * than the principal's tenant and the session's method, and it clears what
     * was bound before.
     *
     * @return void
     */
    public function testLoginVerifiedBindsAsASignInWithTheTenantAndMethodGiven(): void
    {
        $this->session->shouldReceive('getSignInMethod')->andReturn('password');

        $verified = \Mockery::mock(Tenant::class);
        $verified->shouldReceive('getTenantIdentifier')->andReturn('tenant-2');
        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($this->mockIdentity(), $this->mockPrincipal(), $this->mockSession());
        $events->exchangeArray([]);

        $guard->loginVerified($this->identity, $this->principal, $this->session, $verified, 'passkey');

        self::assertSame(
            [Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class],
            array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()),
        );
        self::assertSame($this->identity, $events[0]->user ?? null);
        self::assertSame($this->identity, $events[1]->user ?? null);

        foreach ([...$this->contextsOf($events, PrincipalAssigned::class), ...$this->contextsOf($events, SessionAuthenticated::class)] as $context) {
            EventContextAssertions::assertTenant($verified, $context);
            self::assertSame('passkey', $context->method);
            EventContextAssertions::assertSession($this->session, $context);
        }

        self::assertSame([$this->identity, $this->principal, $this->session], [$guard->user(), $guard->principal(), $guard->session()]);

        $events->exchangeArray([]);

        $guard->loginVerified($this->identity, $this->principal, null, null, null);

        self::assertNull($guard->session());
        self::assertSame([], $this->contextsOf($events, SessionAuthenticated::class));
        EventContextAssertions::assertTenant(null, $this->contextsOf($events, PrincipalAssigned::class)[0]);
    }

    /**
     * `loginVerified()` given a client: the bind events (`PrincipalAssigned`
     * and `SessionAuthenticated`) describe that client rather than the guard's
     * request, Laravel's events are the same as without one, and the guard
     * keeps no client: a later `setSession()` and `setPrincipal()` in the same
     * request describe the request again, as a bind without one does.
     *
     * @return void
     */
    public function testLoginVerifiedDescribesTheClientGivenForThatBindOnly(): void
    {
        $this->session->shouldReceive('getSignInMethod')->andReturn('password');
        $this->request->shouldReceive('ip')->andReturn('10.0.0.1');
        $this->request->shouldReceive('userAgent')->andReturn('Request/1.0');

        $client = new ClientContext('203.0.113.9', 'Console/2.0');
        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->loginVerified($this->identity, $this->principal, $this->session, $this->tenant, 'password', $client);

        self::assertSame(
            [Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class],
            array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()),
        );

        foreach ([...$this->contextsOf($events, PrincipalAssigned::class), ...$this->contextsOf($events, SessionAuthenticated::class)] as $context) {
            self::assertSame($client, $context->client);
        }

        $events->exchangeArray([]);

        $guard->setSession($this->session);
        $guard->setPrincipal($this->principal);

        foreach ([...$this->contextsOf($events, SessionAuthenticated::class), ...$this->contextsOf($events, PrincipalAssigned::class)] as $context) {
            self::assertSame(['10.0.0.1', 'Request/1.0'], [$context->client->ip, $context->client->userAgent]);
        }

        $events->exchangeArray([]);

        $guard->loginVerified($this->identity, $this->principal, $this->session, $this->tenant, 'password');

        self::assertCount(2, [...$this->contextsOf($events, PrincipalAssigned::class), ...$this->contextsOf($events, SessionAuthenticated::class)]);

        foreach ([...$this->contextsOf($events, PrincipalAssigned::class), ...$this->contextsOf($events, SessionAuthenticated::class)] as $context) {
            self::assertSame(['10.0.0.1', 'Request/1.0'], [$context->client->ip, $context->client->userAgent]);
        }
    }

    /**
     * `forgetSession()` resolves nothing and leaves a request not yet resolved
     * alone; it leaves a binding to another session as it is, and forgets one
     * to the session given, whichever instance names it, with no event, keeping
     * the guard signed out for the rest of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgetSessionForgetsOnlyABindingToThatSession(): void
    {
        $other  = $this->mockSession();
        $same   = $this->mockSession();
        $events = $this->recordEvents();
        $guard  = new StubRequestResolvingGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);

        $other->shouldReceive('getSessionIdentifier')->andReturn('session-2');

        $guard->resolvable = $this->identity;

        $guard->forgetSession($this->session);

        self::assertSame(0, $guard->resolutions);
        self::assertSame($this->identity, $guard->user());
        self::assertSame(1, $guard->resolutions);

        $guard->authenticateAs($this->identity, $this->principal, $this->session);
        $guard->forgetSession($other);

        self::assertSame($this->session, $guard->session());

        $events->exchangeArray([]);

        $guard->forgetSession($same);

        self::assertSame([], $events->getArrayCopy());
        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->session());
        self::assertNull($guard->tenant());
        self::assertTrue($guard->guest());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * `forgetIdentity()` resolves nothing and leaves a request not yet resolved
     * alone; it leaves a binding to another identity (another identifier, or
     * the same identifier of another class) as it is, and forgets one to the
     * identity given, whichever instance names it, with no event, keeping the
     * guard signed out for the rest of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgetIdentityForgetsOnlyABindingToThatIdentity(): void
    {
        $bound  = new PlainIdentityFixture(1);
        $events = $this->recordEvents();
        $guard  = new StubRequestResolvingGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);

        $guard->resolvable = $bound;

        $guard->forgetIdentity($bound);

        self::assertSame(0, $guard->resolutions);
        self::assertSame(1, $guard->id());
        self::assertSame(1, $guard->resolutions);

        $guard->authenticateAs($bound, $this->principal, $this->session);
        $guard->forgetIdentity(new PlainIdentityFixture(2));
        $guard->forgetIdentity(new StubIdentity(['id' => 1]));

        self::assertSame(1, $guard->id());
        self::assertSame($this->session, $guard->session());

        $events->exchangeArray([]);

        $guard->forgetIdentity(new PlainIdentityFixture('1'));

        self::assertSame([], $events->getArrayCopy());
        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->session());
        self::assertTrue($guard->guest());
        self::assertSame(1, $guard->resolutions);
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
            /** @var ?array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal, 2: \SineMacula\Laravel\Authentication\Contracts\Session} Context bound on the first `user()` call. */
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

        $guard->pending = [$this->identity, $this->principal, $this->session];

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

    /**
     * The `TenantUnavailableException` the guard's `tenant()` throws, failing
     * the test when it answers instead.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    private static function unavailableTenantOf(AbstractGuard $guard): TenantUnavailableException
    {
        try {
            $guard->tenant();
        } catch (TenantUnavailableException $exception) {
            return $exception;
        }

        self::fail('Expected tenant() to throw TenantUnavailableException.');
    }
}
