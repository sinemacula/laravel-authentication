<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\PinningConnectionResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubModel;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the bearer-token `user()` resolution path on `JwtGuard`.
 *
 * Split out of the original JwtGuardTest so each class stays focused on a
 * single behavioural slice.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
#[CoversClass(JwtGuard::class)]
final class JwtGuardUserResolutionTest extends JwtGuardTestCase
{
    use InteractsWithSessionRecords;

    /** @var string Well-formed id of the session the token names. */
    private const string SESSION_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /** @var string Well-formed id that names no stored session. */
    private const string MISSING_SESSION_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f71';

    /**
     * A request with no Authorization header returns null from `user()` without
     * dispatching anything (there is nothing to attempt).
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenNoBearerTokenPresent(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $this->events->shouldNotReceive('dispatch');
        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * A request whose `Authorization: Bearer` header carries an empty string
     * token returns null without firing any events. Mutation guard: pins the
     * `$token === ''` arm in `JwtGuard::resolveUserFromRequest()` separately
     * from the `null` arm above.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenBearerTokenIsEmptyString(): void
    {
        $guard = $this->makeGuard($this->makeRequest(''));

        $this->events->shouldNotReceive('dispatch');
        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * When the token service cannot parse a token (malformed / bad signature /
     * expired), `user()` reports `token_invalid` once, and nothing else, then
     * returns null.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenTokenServiceCannotParseToken(): void
    {
        $guard = $this->makeGuard($this->makeRequest('not-a-jwt'));

        $this->expectRejection(FailureReason::TOKEN_INVALID);

        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * A rejected token is attempted once per request: repeated `user()`,
     * `check()` and accessor calls neither re-run the lookups nor report the
     * failure again.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserAttemptsARejectedTokenOncePerRequest(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-missing', 'principal' => 'p-1']);
        $guard = $this->makeGuard($this->makeRequest($token));

        $this->expectRejection(FailureReason::IDENTITY_UNKNOWN);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-missing')
            ->andReturnNull();

        self::assertNull($guard->user());
        self::assertNull($guard->user());
        self::assertFalse($guard->check());
        self::assertNull($guard->principal());
    }

    /**
     * A token whose claims array lacks `sub` is reported as `token_invalid` and
     * returns null.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenSubClaimMissing(): void
    {
        $token = $this->encodeAccessToken(['principal' => 'p-1', 'sid' => 'd-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $this->expectRejection(FailureReason::TOKEN_INVALID);

        $this->provider->shouldNotReceive('retrieveById');

        self::assertNull($guard->user());
    }

    /**
     * An access token without `principal` is rejected before any lookup,
     * instead of falling back to the resolver's default principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserRejectsTokenWithoutPrincipalClaimInsteadOfUsingTheDefault(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $this->expectRejection(FailureReason::TOKEN_INVALID);

        $this->provider->shouldNotReceive('retrieveById');
        $this->resolver->shouldNotReceive('resolve');

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveById()` returns null, `user()` returns null.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenIdentityNotFound(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturnNull();

        $this->resolver->shouldNotReceive('resolve');

        $this->expectRejection(FailureReason::IDENTITY_UNKNOWN);

        self::assertNull($guard->user());
    }

    /**
     * When `retrieveById()` returns an Authenticatable that is not an Identity,
     * `user()` returns null.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenResolvedUserIsNotIdentity(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $nonIdentity = \Mockery::mock(Authenticatable::class);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($nonIdentity);

        $this->resolver->shouldNotReceive('resolve');

        $this->expectRejection(FailureReason::IDENTITY_UNKNOWN);

        self::assertNull($guard->user());
    }

    /**
     * When `resolver->resolve()` returns null, `user()` returns null.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenResolverProducesNoPrincipal(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturnNull();

        $this->expectRejection(FailureReason::PRINCIPAL_MISMATCH);

        self::assertNull($guard->user());
    }

    /**
     * When the resolved principal's `isActive()` returns false, `user()`
     * returns null.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenResolvedPrincipalIsInactive(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->byDefault()->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnFalse();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::PRINCIPAL_INACTIVE);

        self::assertNull($guard->user());
    }

    /**
     * The resolver's `UnresolvableIdentityException` is a misconfiguration: it
     * propagates out of `user()` as a server error instead of being reported as
     * a failed bearer token.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserPropagatesUnresolvableIdentityException(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);
        $exception = new UnresolvableIdentityException('cannot resolve');

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andThrow($exception);

        $this->events->shouldNotReceive('dispatch');

        try {
            $guard->user();
            self::fail('Expected the UnresolvableIdentityException to propagate.');
        } catch (UnresolvableIdentityException $caught) {
            self::assertSame($exception, $caught);
        }
    }

    /**
     * A principal acting within a `CanBeActive` tenant that reports inactive is
     * rejected by `user()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenPrincipalTenantIsInactive(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('getTenantIdentifier')->byDefault()->andReturn('tenant-1');
        $tenant->shouldReceive('isActive')->once()->andReturnFalse();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('getTenant')
            ->once()
            ->andReturn($tenant);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::TENANT_INACTIVE);

        self::assertNull($guard->user());
    }

    /**
     * Activation is opt-in: a principal that does not implement `CanBeActive`
     * is bound without consulting any active flag.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserBindsPrincipalWithoutActivationCapability(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->events->shouldReceive('dispatch');

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
    }

    /**
     * A `CanBeActive` identity reporting `false` is rejected by `user()` after
     * `retrieveById()` returns it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReturnsNullWhenIdentityIsInactive(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class, CanBeActive::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);
        $identity->shouldReceive('isActive')->once()->andReturnFalse();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldNotReceive('resolve');

        $this->expectRejection(FailureReason::IDENTITY_INACTIVE);

        self::assertNull($guard->user());
    }

    /**
     * When `sub` resolves to a real identity but a fail-closed `principal`
     * branch rejects the token, the failure is still attributed to the resolved
     * identity, with no principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserAttributesTheFailureToTheResolvedIdentityWhenPidHintRejectsToken(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-hinted']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->byDefault()->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-default');

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::PRINCIPAL_MISMATCH, static fn (EventContext $context): bool => $context->identity === $identity && $context->principal === null);

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the token carries a `principal` hint but the resolver
     * returns `null` (the hinted principal cannot be resolved), `user()`
     * rejects the token rather than falling back to the default principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserRejectsTokenWhenPidHintResolvesToNullPrincipal(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-hinted']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

        $this->expectRejection(FailureReason::PRINCIPAL_MISMATCH);

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the token carries a `principal` hint but the resolver
     * returns a *different* principal (because it fell through to the default),
     * `user()` returns null rather than silently downgrading the active
     * principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserRejectsTokenWhenPidHintDoesNotMatchResolvedPrincipal(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-hinted']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->byDefault()->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-default');

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::PRINCIPAL_MISMATCH);

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the resolver returns a principal whose identifier
     * stringifies to `null` (e.g. an unsaved Eloquent model returned from a
     * misbehaving custom resolver), the guard MUST reject the token rather than
     * bind a transient actor. Pins the fail-closed `null` arm of
     * `IdentifierCoercion::matches()`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserRejectsTokenWhenResolvedPrincipalIdentifierIsNull(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-hinted']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getTenant')->byDefault()->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn(null);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::PRINCIPAL_MISMATCH);

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: when the token carries a `sid` hint but the session lookup
     * fails, `user()` returns null rather than silently binding the identity
     * with no session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserRejectsTokenWhenDidHintCannotBeResolved(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::MISSING_SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('getModel')
            ->once()
            ->andReturn(new StubSession);
        $builder->shouldReceive('find')
            ->once()
            ->with(self::MISSING_SESSION_ID)
            ->andReturnNull();

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')
            ->once()
            ->andReturn($builder);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::SESSION_UNKNOWN);

        self::assertNull($guard->user());
    }

    /**
     * Fail-closed: a `sid` naming a revoked session is rejected as
     * `session_revoked`, from the single lookup that loaded it, attributed to
     * the resolved identity and the session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserRejectsTokenWhenDidHintNamesRevokedSession(): void
    {
        $session = new StubSession([...self::liveSession(self::GUARD_NAME), 'id' => self::SESSION_ID, 'revoked_at' => $this->now]);

        $this->assertDidHintIsRejected($session, FailureReason::SESSION_REVOKED);
    }

    /**
     * Rows of `[idle deadline, absolute deadline]` of ended sessions, in
     * seconds from the frozen clock.
     *
     * @return iterable<string, array{0: ?int, 1: ?int}>
     */
    public static function provideEndedSessions(): iterable
    {
        yield from [
            'idle reached this second'     => [0, 3600],
            'absolute reached this second' => [3600, 0],
            'absolute passed'              => [3600, -1],
            'no idle deadline'             => [null, 3600],
        ];
    }

    /**
     * Fail-closed: a `sid` naming a session that has ended is rejected as
     * `session_expired`, from the single lookup that loaded it, whatever the
     * token's own expiry.
     *
     * @param  ?int  $idleIn
     * @param  ?int  $absoluteIn
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideEndedSessions')]
    public function testUserRejectsTokenWhenDidHintNamesSessionThatHasEnded(?int $idleIn, ?int $absoluteIn): void
    {
        $this->assertDidHintIsRejected(new StubSession([
            'id'                  => self::SESSION_ID,
            'guard'               => self::GUARD_NAME,
            'status'              => 'active',
            'revoked_at'          => null,
            'idle_expires_at'     => $idleIn     === null ? null : $this->now->copy()->addSeconds($idleIn),
            'absolute_expires_at' => $absoluteIn === null ? null : $this->now->copy()->addSeconds($absoluteIn),
        ]), FailureReason::SESSION_EXPIRED);
    }

    /**
     * A `sid` naming a session loaded without its revocation column is reported
     * as a misconfiguration rather than read as "not revoked", so no user is
     * bound.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReportsDidHintNamingSessionLoadedWithoutItsRevocation(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')->andReturnSelf();
        $builder->shouldReceive('getModel')->andReturn(new StubSession);
        $builder->shouldReceive('find')
            ->once()
            ->with(self::SESSION_ID)
            ->andReturn(new StubSession([...self::liveSession(self::GUARD_NAME), 'id' => self::SESSION_ID]));

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')->andReturn($builder);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')->with('i-1')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->with($identity, 'p-1')->andReturn($principal);
        $this->events->shouldReceive('dispatch');

        try {
            $guard->user();

            self::fail('The unloaded revocation column should have been reported.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('its `revoked_at` attribute is not loaded', $exception->getMessage());
        }

        self::assertFalse($guard->hasUser());
    }

    /**
     * A `sid` looked up through a `sessions()` relation over a model that is
     * not an `EloquentSession` is reported as the misconfiguration it is,
     * before the relation is queried, rather than read as an unknown session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserReportsASessionsRelationOverAModelThatIsNotASession(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')->andReturnSelf();
        $builder->shouldReceive('getModel')->andReturn(new StubModel);
        $builder->shouldNotReceive('find');

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')->andReturn($builder);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')->with('i-1')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->with($identity, 'p-1')->andReturn($principal);
        $this->events->shouldNotReceive('dispatch');

        try {
            $guard->user();

            self::fail('The sessions relation over another model should have been reported.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('must query a model that implements', $exception->getMessage());
        }

        self::assertFalse($guard->hasUser());
    }

    /**
     * The identity's sessions relation is built while reads are pinned to the
     * write connection, so a relation that queries while it is built cannot
     * read a lagging replica.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserBuildsTheSessionsRelationWithReadsPinnedToTheWriteConnection(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')->andReturnSelf();
        $builder->shouldReceive('getModel')->andReturn(new StubSession);
        $builder->shouldReceive('find')
            ->with(self::SESSION_ID)
            ->andReturn(new StubSession([...self::liveSession(self::GUARD_NAME, $principal), 'id' => self::SESSION_ID, 'revoked_at' => null]));

        $resolvers = [];

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')
            ->once()
            ->andReturnUsing(static function () use ($builder, &$resolvers): Builder {
                $resolvers[] = Model::getConnectionResolver();

                return $builder;
            });

        $this->provider->shouldReceive('retrieveById')->with('i-1')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->with($identity, 'p-1')->andReturn($principal);
        $this->events->shouldReceive('dispatch');

        self::assertNotNull($guard->user());
        self::assertSame($identity, $guard->identity());
        self::assertCount(1, $resolvers);
        self::assertInstanceOf(PinningConnectionResolver::class, $resolvers[0]);
        self::assertNotInstanceOf(PinningConnectionResolver::class, Model::getConnectionResolver());
    }

    /**
     * A `sid` that cannot be a key of the identity's session model is rejected
     * as `session_unknown` without querying the sessions relation, attributed
     * to the resolved identity and principal and to the id the token named.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserRejectsMalformedDidHintWithoutQueryingSessions(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => 'not-a-uuid']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('getModel')
            ->once()
            ->andReturn(new StubSession);
        $builder->shouldNotReceive('find');

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')
            ->once()
            ->andReturn($builder);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::SESSION_UNKNOWN, static fn (EventContext $context): bool => $context->identity === $identity
            && $context->principal                                                                                           === $principal
            && $context->session                                                                                             === null
            && $context->sessionId                                                                                           === 'not-a-uuid');

        self::assertNull($guard->user());
    }

    /**
     * A database error while looking up a well-formed `sid` propagates as a
     * server error instead of reading as a missing session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserPropagatesDatabaseErrorFromSessionLookup(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $failure = new QueryException('testing', 'select', [], new \PDOException('server has gone away'));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('getModel')
            ->once()
            ->andReturn(new StubSession);
        $builder->shouldReceive('find')
            ->once()
            ->with(self::SESSION_ID)
            ->andThrow($failure);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')
            ->once()
            ->andReturn($builder);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->events->shouldNotReceive('dispatch');

        $this->expectExceptionObject($failure);

        $guard->user();
    }

    /**
     * When the `sid` fail-closed branch rejects a token after `sub` already
     * resolved, the failure carries that resolved identity and principal, and
     * the session id the token named, for attribution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserAttributesTheFailureToTheResolvedIdentityWhenDidHintCannotBeResolved(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::MISSING_SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('getModel')
            ->once()
            ->andReturn(new StubSession);
        $builder->shouldReceive('find')
            ->once()
            ->with(self::MISSING_SESSION_ID)
            ->andReturnNull();

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')
            ->once()
            ->andReturn($builder);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->expectRejection(FailureReason::SESSION_UNKNOWN, static fn (EventContext $context): bool => $context->identity === $identity
            && $context->principal                                                                                           === $principal
            && $context->session                                                                                             === null
            && $context->sessionId                                                                                           === self::MISSING_SESSION_ID
            && $context->guard                                                                                               === self::GUARD_NAME);

        self::assertNull($guard->user());
    }

    /**
     * A valid token whose claims include `sub`, `principal`, and `sid` results
     * in the guard binding the identity, principal, and session and dispatching
     * only `Authenticated`, `PrincipalAssigned` and `SessionAuthenticated`: a
     * request's token is an authentication, not a sign-in, so no `Attempting`,
     * `Validated` or `Login`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserBindsIdentityPrincipalAndSessionFromValidToken(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $session = new StubSession([...self::liveSession(self::GUARD_NAME, $principal), 'id' => self::SESSION_ID, 'revoked_at' => null]);

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('getModel')
            ->once()
            ->andReturn(new StubSession);
        $builder->shouldReceive('find')
            ->once()
            ->with(self::SESSION_ID)
            ->andReturn($session);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')
            ->once()
            ->andReturn($builder);

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertNotNull($guard->user());
        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertSame($session, $guard->session());

        self::assertSame([Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class], $dispatched);
    }

    /**
     * A valid token without a `sid` claim binds identity + principal and does
     * NOT fire `SessionAuthenticated`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testUserSkipsSessionWhenNoDidClaimPresent(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->byDefault()->andReturn(1);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event::class;
            });

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
        self::assertNull($guard->session());
        self::assertNotContains(SessionAuthenticated::class, $dispatched);
    }

    /**
     * Assert a bearer token whose `sid` names the supplied session is rejected
     * for the reason from the single lookup that loaded it, attributed to the
     * resolved identity and the session.
     *
     * @param  \Tests\Unit\Stubs\StubSession  $session
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function assertDidHintIsRejected(StubSession $session, FailureReason $reason): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1', 'sid' => self::SESSION_ID]);

        $guard = $this->makeGuard($this->makeRequest($token));

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('getModel')
            ->once()
            ->andReturn(new StubSession);
        $builder->shouldReceive('find')
            ->once()
            ->with(self::SESSION_ID)
            ->andReturn($session);

        /** @var \Mockery\MockInterface&\Tests\Unit\Stubs\StubIdentity $identity */
        $identity = \Mockery::mock(StubIdentity::class)->makePartial();
        $identity->shouldReceive('sessions')
            ->once()
            ->andReturn($builder);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->expectRejection($reason, static fn (EventContext $context): bool => $context->identity === $identity && $context->session === $session);

        self::assertNull($guard->user());
        self::assertNull($guard->session());
    }

    /**
     * Expect the request's token to be reported once as rejected for the
     * reason, with nothing else dispatched, and its context to pass the check
     * when one is given.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?\Closure(\SineMacula\Laravel\Authentication\Events\EventContext): bool  $context
     * @return void
     */
    private function expectRejection(FailureReason $reason, ?\Closure $context = null): void
    {
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                && $event->flow           === AuthenticationFlow::BEARER
                && $event->reason         === $reason
                && $event->context->guard === self::GUARD_NAME
                && ($context === null || $context($event->context))));
    }
}
