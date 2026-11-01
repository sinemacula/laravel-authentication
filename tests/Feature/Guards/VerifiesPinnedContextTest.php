<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\Relation;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use Tests\Unit\Stubs\Stub3dPrincipal;
use Tests\Unit\Stubs\StubPinnedContextGuard;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the principal and session a caller pins on `attempt()`:
 * each is bound only once proven to belong to the authenticated identity, and a
 * pin that fails the check fails the attempt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(VerifiesPinnedContext::class)]
final class VerifiesPinnedContextTest extends AbstractGuardTestCase
{
    /** @var string A key with the shape of a `StubSession` UUID key. */
    private const string SESSION_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /** @var array<int, class-string> Classes of the dispatched events. */
    private array $dispatched = [];

    /** @var ?\SineMacula\Laravel\Authentication\Guards\AbstractGuard Guard of the last `guardAttempt()`. */
    private ?AbstractGuard $lastGuard = null;

    /**
     * Accept the credentials of a fresh identity and record dispatched events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider->shouldReceive('validateCredentials')->andReturnTrue();

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(function (object $event): void {
                $this->dispatched[] = $event::class;
            });
    }

    /**
     * A pinned principal whose identifier resolves to a different principal
     * (the resolver falling back to the identity's default) fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalResolvingToAnotherPrincipalFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $pinned   = $this->principal('p-other');
        $fallback = $this->principal('p-default');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-other')->andReturn($fallback);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * A pinned principal of another class that shares the identifier of one the
     * identity owns fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalOfAnotherClassWithACollidingIdentifierFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $pinned = \Mockery::mock(Principal::class, CanBeActive::class);
        $pinned->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');

        $owned = $this->principal('p-1');

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($owned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * A pinned principal with no identifier (unsaved) cannot be proven and
     * fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalWithoutIdentifierFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $pinned = $this->principal(null);

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * When the resolver resolves nothing for a pinned principal the attempt
     * fails.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalTheResolverCannotResolveFailsTheAttempt(): void
    {
        $identity = $this->acceptIdentity($this->mockIdentity());

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturnNull();

        $this->assertAttemptFails($this->guardAttempt($this->principal('p-1')));
    }

    /**
     * A principal of another identity fails the attempt even when the resolver
     * returns it for the hint, as one whose hinted lookup is not scoped to the
     * identity does: the guard checks the principal's own identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalOwnedByAnotherIdentityFailsTheAttempt(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $victim = $this->mockIdentity();
        $victim->shouldReceive('getAuthIdentifier')->andReturn(8);

        $pinned = $this->principal('p-victim', $victim);

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-victim')->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * A principal owned by an identity of another class that shares the
     * authenticated identity's identifier fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalOwnedByAnIdentityOfAnotherClassWithACollidingIdentifierFailsTheAttempt(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $other = $this->mockIdentity(HasSessions::class);
        $other->shouldReceive('getAuthIdentifier')->andReturn(7);

        $pinned = $this->principal('p-1', $other);

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * A pinned principal whose owner cannot be read (its `getIdentity()` throws
     * a `LogicException`, as for a deleted owner) is not owned, so it fails the
     * attempt instead of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalWhoseOwnerCannotBeReadFailsTheAttempt(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $pinned = $this->principal('p-1');
        $pinned->shouldReceive('getIdentity')->andThrow(new \LogicException('The owner cannot be loaded.'));

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * A pinned `ActsAsPrincipal` model without an identity relation (the shape
     * of a principal that never declared `identity()`) cannot report an owner,
     * so it fails the attempt instead of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalWithoutAnOwnerRelationFailsTheAttempt(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $pinned = new Stub3dPrincipal;
        $pinned->forceFill(['id' => 5]);

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 5)->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * Under Eloquent's strict missing-attribute mode, a persisted pinned
     * `ActsAsPrincipal` model without an identity relation still fails the
     * attempt instead of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalWithoutAnOwnerRelationFailsTheAttemptUnderStrictMode(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $pinned = new Stub3dPrincipal;
        $pinned->forceFill(['id' => 5]);
        $pinned->exists = true;

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 5)->andReturn($pinned);

        Model::preventAccessingMissingAttributes();

        try {
            $result = $this->guardAttempt($pinned);
        } finally {
            Model::preventAccessingMissingAttributes(false);
        }

        $this->assertAttemptFails($result);
    }

    /**
     * A pinned principal hydrated with lazy loading prevented (one of several
     * rows under Eloquent's strict mode) is still proven owned: the package
     * re-reads its owner on purpose, so that read is not a lazy-loading
     * violation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalHydratedWithLazyLoadingPreventedIsOwned(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $owner = \Mockery::mock(BelongsTo::class);
        $owner->shouldReceive('getResults')->once()->andReturn($identity);

        // A subclass of its own, so the resolved relation stays off the shared
        // stub class.
        $pinned = new class extends Stub3dPrincipal {};

        $pinned::resolveRelationUsing('identity', static fn (): Relation => $owner);

        $pinned->forceFill(['id' => 5]);
        $pinned->exists              = true;
        $pinned->preventsLazyLoading = true;

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 5)->andReturn($pinned);

        self::assertTrue($this->guardAttempt($pinned));
        self::assertSame($pinned, $this->lastGuard?->principal());
    }

    /**
     * An identity relation already set on the resolved principal does not vouch
     * for it: the owner is read from the principal's own stored key, so a
     * principal that names the identity only through a preloaded relation fails
     * the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedPrincipalVouchedForOnlyByAPreloadedOwnerRelationFailsTheAttempt(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $pinned = new Stub3dPrincipal;
        $pinned->forceFill(['id' => 5]);
        $pinned->setRelation('identity', $identity);

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 5)->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
        self::assertSame($identity, $pinned->getIdentity());
    }

    /**
     * An owned but inactive pinned principal fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInactivePinnedPrincipalFailsTheAttempt(): void
    {
        $identity = $this->mockIdentity();
        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $this->acceptIdentity($identity);

        $pinned = \Mockery::mock(Principal::class, CanBeActive::class);
        $pinned->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $pinned->shouldReceive('getIdentity')->andReturn($identity);
        $pinned->shouldReceive('isActive')->andReturnFalse();

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($pinned);

        $this->assertAttemptFails($this->guardAttempt($pinned));
    }

    /**
     * An owned, live pinned session binds the identity's own row rather than
     * the caller's instance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOwnedLivePinnedSessionBindsTheIdentitysOwnRow(): void
    {
        $principal = $this->principal('p-1');
        $pinned    = $this->record(self::SESSION_ID, null, $principal);
        $owned     = $this->record(self::SESSION_ID, null, $principal);

        $guard = $this->guardWithSessions($owned, $principal);

        self::assertTrue($guard->attempt(['email' => 'x'], null, $pinned));
        self::assertSame($owned, $guard->session());
    }

    /**
     * Rows of `[identifier of the principal the session records, or null for
     * none]` other than the principal being bound.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideOtherPrincipals(): iterable
    {
        yield from [
            'another principal' => ['p-2'],
            'no principal'      => [null],
        ];
    }

    /**
     * An owned, live pinned session that acts as another principal, or as none,
     * fails the attempt: a session is bound only for the principal it records.
     *
     * @param  ?string  $recorded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOtherPrincipals')]
    public function testPinnedSessionActingAsAnotherPrincipalFailsTheAttempt(?string $recorded): void
    {
        $owned = $this->record(self::SESSION_ID, null, $recorded === null ? null : $this->principal($recorded));
        $guard = $this->guardWithSessions($owned, $this->principal('p-1'));

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $owned), $guard);
    }

    /**
     * A pinned session the identity does not own fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedSessionTheIdentityDoesNotOwnFailsTheAttempt(): void
    {
        $guard = $this->guardWithSessions(null);

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $this->record(self::SESSION_ID, null)), $guard);
    }

    /**
     * A revoked pinned session fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokedPinnedSessionFailsTheAttempt(): void
    {
        $revoked = $this->record(self::SESSION_ID, CarbonImmutable::now());

        $guard = $this->guardWithSessions($revoked);

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $revoked), $guard);
    }

    /**
     * Rows of `[guard]` a session may record other than the attempting guard.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideOtherGuards(): iterable
    {
        yield from [
            'another guard' => ['admin'],
            'no guard'      => [null],
        ];
    }

    /**
     * A pinned session of another guard's sessions, or of none, fails the
     * attempt like a missing one.
     *
     * @param  ?string  $guard
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOtherGuards')]
    public function testPinnedSessionOfAnotherGuardFailsTheAttempt(?string $guard): void
    {
        $foreign = \Mockery::mock(Session::class);
        $foreign->shouldReceive('getSessionIdentifier')->andReturn(self::SESSION_ID);
        $foreign->shouldReceive('getRevokedAt')->andReturnNull();
        $foreign->shouldReceive('getGuard')->andReturn($guard);
        $foreign->shouldReceive('getIdleExpiresAt')->andReturn(CarbonImmutable::now()->addDays(90));
        $foreign->shouldReceive('getAbsoluteExpiresAt')->andReturn(CarbonImmutable::now()->addDays(180));

        $guard = $this->guardWithSessions($foreign);

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $foreign), $guard);
    }

    /**
     * A pinned session that has ended fails the attempt, like a revoked one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEndedPinnedSessionFailsTheAttempt(): void
    {
        $ended = \Mockery::mock(Session::class);
        $ended->shouldReceive('getSessionIdentifier')->andReturn(self::SESSION_ID);
        $ended->shouldReceive('getGuard')->andReturn(self::GUARD_NAME);
        $ended->shouldReceive('getRevokedAt')->andReturnNull();
        $ended->shouldReceive('getIdleExpiresAt')->andReturn(CarbonImmutable::now());
        $ended->shouldReceive('getAbsoluteExpiresAt')->andReturn(CarbonImmutable::now()->addDay());

        $guard = $this->guardWithSessions($ended);

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $ended), $guard);
    }

    /**
     * A pinned session of another class that shares the identifier of a session
     * the identity owns fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedSessionOfAnotherClassWithACollidingIdentifierFailsTheAttempt(): void
    {
        $pinned = \Mockery::mock(Session::class, CanBeActive::class);
        $pinned->shouldReceive('getSessionIdentifier')->andReturn(self::SESSION_ID);

        $guard = $this->guardWithSessions($this->record(self::SESSION_ID, null));

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $pinned), $guard);
    }

    /**
     * A pinned session with no identifier cannot be looked up and fails the
     * attempt without querying.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedSessionWithoutIdentifierFailsTheAttempt(): void
    {
        $sessions = \Mockery::mock(Builder::class);
        $sessions->shouldNotReceive('useWritePdo');
        $sessions->shouldNotReceive('find');

        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldReceive('sessions')->andReturn($sessions);

        $this->acceptIdentity($identity);
        $this->resolver->shouldReceive('resolve')->andReturn($this->principal('p-1'));

        $guard = $this->makeGuard();

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $this->record(null, null)), $guard);
    }

    /**
     * A pinned session whose identifier cannot be a key of the identity's
     * session model fails the attempt without querying, as a malformed `did`
     * does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedSessionWithMalformedIdentifierFailsTheAttemptWithoutQuerying(): void
    {
        $sessions = $this->writerSessions();
        $sessions->shouldNotReceive('find');

        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldReceive('sessions')->andReturn($sessions);

        $this->acceptIdentity($identity);
        $this->resolver->shouldReceive('resolve')->andReturn($this->principal('p-1'));

        $guard = $this->makeGuard();

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $this->record('not-a-uuid', null)), $guard);
    }

    /**
     * A pinned session on an identity that cannot own sessions cannot be proven
     * and fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPinnedSessionOnIdentityWithoutSessionsFailsTheAttempt(): void
    {
        $this->acceptIdentity($this->mockIdentity());
        $this->resolver->shouldReceive('resolve')->andReturn($this->principal('p-1'));

        $guard = $this->makeGuard();

        $this->assertAttemptFails($guard->attempt(['email' => 'x'], null, $this->record(self::SESSION_ID, null)), $guard);
    }

    /**
     * The pinned-principal, pinned-session, and session-hint checks are
     * callable from a guard subclass, as `JwtGuard` calls the session-hint
     * lookup, and return the identity's own instances.
     *
     * @return void
     */
    public function testPinnedChecksAreAvailableToGuardSubclasses(): void
    {
        $guard = $this->makeStubGuard();

        $identity  = $this->mockIdentity(HasSessions::class);
        $principal = $this->principal('p-1', $identity);
        $session   = $this->record(self::SESSION_ID, null, $principal);

        $identity->shouldReceive('getAuthIdentifier')->andReturn(7);

        $sessions = \Mockery::mock(Builder::class);
        $sessions->shouldReceive('useWritePdo')->twice()->andReturnSelf();
        $sessions->shouldReceive('getModel')->andReturn(new StubSession);
        $sessions->shouldReceive('find')->twice()->with(self::SESSION_ID)->andReturn($session);

        $identity->shouldReceive('sessions')->andReturn($sessions);

        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($principal);

        self::assertSame($principal, $guard->pinnedPrincipal($identity, $principal));
        self::assertSame($session, $guard->pinnedSession($identity, $principal, $session));
        self::assertSame($session, $guard->sessionFromHint($identity, self::SESSION_ID));
    }

    /**
     * Build the subclass test double over the shared collaborators.
     *
     * @return \Tests\Unit\Stubs\StubPinnedContextGuard
     */
    private function makeStubGuard(): StubPinnedContextGuard
    {
        return new StubPinnedContextGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);
    }

    /**
     * Make the provider return the identity for any credentials.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function acceptIdentity(Identity $identity): Identity
    {
        $this->provider->shouldReceive('retrieveByCredentials')->andReturn($identity);

        return $identity;
    }

    /**
     * Attempt with the pinned principal on a fresh guard, keeping the guard for
     * assertions.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @return bool
     *
     * @throws \Throwable
     */
    private function guardAttempt(Principal $pinned): bool
    {
        $this->lastGuard = $this->makeGuard();

        return $this->lastGuard->attempt(['email' => 'x'], $pinned);
    }

    /**
     * Assert the attempt failed: `false`, `Failed` dispatched, no `Login`, and
     * nothing bound.
     *
     * @param  bool  $result
     * @param  ?\SineMacula\Laravel\Authentication\Guards\AbstractGuard  $guard
     * @return void
     */
    private function assertAttemptFails(bool $result, ?AbstractGuard $guard = null): void
    {
        $guard ??= $this->lastGuard;

        self::assertFalse($result);
        self::assertContains(Failed::class, $this->dispatched);
        self::assertNotContains(Login::class, $this->dispatched);
        self::assertNotNull($guard);
        self::assertFalse($guard->hasUser());
    }

    /**
     * Build a guard whose authenticated identity owns the supplied session (or
     * none) and resolves the principal, or an active one.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $owned
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function guardWithSessions(?Session $owned, ?Principal $principal = null): AbstractGuard
    {
        $sessions = $this->writerSessions();
        $sessions->shouldReceive('find')->once()->with(self::SESSION_ID)->andReturn($owned);

        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldReceive('sessions')->andReturn($sessions);

        $this->acceptIdentity($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($principal ?? $this->principal('p-1'));

        return $this->makeGuard();
    }

    /**
     * Build a sessions relation over `StubSession` that expects to be routed to
     * the write connection once.
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Tests\Unit\Stubs\StubSession>&\Mockery\MockInterface
     */
    private function writerSessions(): MockInterface
    {
        $sessions = \Mockery::mock(Builder::class);
        $sessions->shouldReceive('useWritePdo')->once()->andReturnSelf();
        $sessions->shouldReceive('getModel')->andReturn(new StubSession);

        return $sessions;
    }

    /**
     * Build a principal without the activation capability that acts within no
     * tenant, owned by the supplied identity when one is given.
     *
     * @param  ?string  $identifier
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principal(?string $identifier, ?Identity $owner = null): MockInterface
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn($identifier);
        $principal->shouldReceive('getTenant')->andReturnNull();

        if ($owner !== null) {
            $principal->shouldReceive('getIdentity')->andReturn($owner);
        }

        return $principal;
    }

    /**
     * Build a session with the supplied identifier and revocation time, in a
     * session of the guard that started now, acting as the principal when one
     * is given.
     *
     * @param  ?string  $identifier
     * @param  ?\Carbon\CarbonImmutable  $revokedAt
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \Tests\Unit\Stubs\StubSession
     */
    private function record(?string $identifier, ?CarbonImmutable $revokedAt, ?Principal $principal = null): StubSession
    {
        return new StubSession([
            'id'                  => $identifier,
            'guard'               => self::GUARD_NAME,
            'principal_type'      => $principal === null ? null : PrincipalReference::type($principal),
            'principal_id'        => $principal === null ? null : PrincipalReference::id($principal),
            'revoked_at'          => $revokedAt,
            'idle_expires_at'     => CarbonImmutable::now()->addDays(90),
            'absolute_expires_at' => CarbonImmutable::now()->addDays(180),
        ]);
    }
}
