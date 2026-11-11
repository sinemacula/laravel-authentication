<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Events\Dispatcher;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for identity and principal resolution in `JwtGuard`'s
 * refresh-token exchange, and the successful refresh.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(IdentifierCoercion::class)]
final class JwtGuardRefreshResolutionTest extends JwtGuardTestCase
{
    use InteractsWithSessionRecords;

    /**
     * When the bound identity reports `isActive() === false`, refresh fails
     * with `identity_inactive` and dispatches `AuthenticationFailed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenIdentityIsInactive(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new class extends StubIdentity implements CanBeActive {
            /**
             * Report the identity as deactivated.
             *
             * @return bool
             */
            #[\Override]
            public function isActive(): bool
            {
                return false;
            }
        };
        $identity->forceFill(['id' => 21]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => '21',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->resolver->shouldNotReceive('resolve');

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::IDENTITY_INACTIVE),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * Provider answers for the owner key `9` of a `StubIdentity` session that
     * are not that owner.
     *
     * @return iterable<string, array{0: \Closure(): mixed}>
     */
    public static function provideAnswersThatAreNotTheSessionOwner(): iterable
    {
        yield from [
            'no identity through the provider'           => [static fn (): null => null],
            'an authenticatable that is not an identity' => [static fn (): StubAuthenticatableModel => (new StubAuthenticatableModel)->forceFill(['id' => 9])],
            'another identity model with the owner key'  => [static fn (): StubPrincipal => (new StubPrincipal)->forceFill(['id' => 9])],
            'the owner model with another key'           => [static fn (): StubIdentity => (new StubIdentity)->forceFill(['id' => 10])],
            'an identity that is not an eloquent model'  => [static fn (): Identity => \Mockery::mock(Identity::class)],
        ];
    }

    /**
     * Refresh accepts only the exact session owner the provider reloads,
     * failing as `identity_unknown` otherwise.
     *
     * @param  \Closure(): mixed  $answer
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideAnswersThatAreNotTheSessionOwner')]
    public function testRefreshRejectsAProviderAnswerThatIsNotTheSessionOwner(\Closure $answer): void
    {
        $plainRotationId = 'stored-rotation-id';

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $answer());

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->resolver->shouldNotReceive('resolve');

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason             === FailureReason::IDENTITY_UNKNOWN
                    && $event->context->sessionId === $session->id),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A session row with no owner key has no owner to reload: refresh fails
     * with `identity_unknown` without asking the provider.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsASessionWithoutAnOwnerKeyWithoutAskingTheProvider(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->provider->shouldNotReceive('retrieveById');
        $this->resolver->shouldNotReceive('resolve');

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::IDENTITY_UNKNOWN),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A refresh whose `principal` hint the resolver cannot resolve fails as
     * `principal_unresolved`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenPrincipalIsUnresolved(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 9]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '9',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

        $token = $this->encodeRefreshToken([
            'principal' => 'p-hinted',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason             === FailureReason::PRINCIPAL_MISMATCH
                    && $event->context->sessionId === $session->id),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * When a refresh token carries a `principal` hint but the resolver returns
     * a different principal, refresh fails with `principal_mismatch`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenPidHintDoesNotMatchResolvedPrincipal(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 10]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '10',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->once()
            ->andReturn('p-default');

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'principal' => 'p-hinted',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason             === FailureReason::PRINCIPAL_MISMATCH
                    && $event->context->sessionId === $session->id),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A hinted principal whose identifier is `null` is rejected rather than
     * rebound as a transient principal.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenResolvedPrincipalIdentifierIsNull(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 15]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '15',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')
            ->once()
            ->andReturn(null);

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'principal' => 'p-hinted',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason             === FailureReason::PRINCIPAL_MISMATCH
                    && $event->context->sessionId === $session->id),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * When the hinted principal reports `isActive() === false`, refresh fails
     * with `principal_inactive` and dispatches `AuthenticationFailed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenPrincipalIsInactive(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 11]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '11',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-11');
        $principal->shouldReceive('isActive')->once()->andReturnFalse();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-11')
            ->andReturn($principal);

        $token = $this->encodeRefreshToken([
            'principal' => 'p-11',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::PRINCIPAL_INACTIVE),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A refresh whose hinted `principal` resolves to `null` rejects the token.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsTokenWhenNullPrincipalResolvesForPidHint(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 25]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '25',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();
        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-hinted')
            ->andReturnNull();

        $token = $this->encodeRefreshToken([
            'principal' => 'p-hinted',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::PRINCIPAL_MISMATCH),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A successful refresh carries the same `principal` through the rotated
     * refresh token and the new access token.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRotatesAndIssuesNewTokenPairOnSuccess(): void
    {
        $plainRotationId = 'stored-rotation-id';
        $oldDigest       = RefreshTokenHasher::hash($plainRotationId);

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 7]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => $oldDigest,
        ])->save();

        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $session->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'principal' => 'p-1',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        $result = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session?->tokens;

        self::assertInstanceOf(TokenPair::class, $result);

        $accessClaims = $this->tokens->parse($result->accessToken->reveal(), TokenType::ACCESS);
        self::assertIsArray($accessClaims);
        self::assertSame('7', $accessClaims[Claims::SUBJECT->value]);
        self::assertSame('p-1', $accessClaims[Claims::PRINCIPAL->value]);
        self::assertSame($session->id, $accessClaims[Claims::SESSION_ID->value]);

        $refreshClaims = $this->tokens->parse(self::bodyRefreshToken($result), TokenType::REFRESH);
        self::assertIsArray($refreshClaims);
        self::assertSame($session->id, $refreshClaims[Claims::SESSION_ID->value]);
        self::assertSame('p-1', $refreshClaims[Claims::PRINCIPAL->value]);
        self::assertIsString($refreshClaims[Claims::JWT_ID->value]);
        self::assertNotSame($plainRotationId, $refreshClaims[Claims::JWT_ID->value]);

        $fresh = StubSession::query()->findOrFail($session->id);
        self::assertNotSame($oldDigest, $fresh->refresh_key);
        self::assertNotNull($fresh->refresh_key);
        self::assertTrue(RefreshTokenHasher::verify($refreshClaims[Claims::JWT_ID->value], $fresh->refresh_key));

        $refreshed = array_values(
            array_filter(
                $dispatched,
                static fn (object $event): bool => $event instanceof Refreshed,
            ),
        );

        self::assertCount(1, $refreshed);
        self::assertInstanceOf(Refreshed::class, $refreshed[0]);
        self::assertSame(self::GUARD_NAME, $refreshed[0]->context->guard);
        EventContextAssertions::assertIdentity($identity, $refreshed[0]->context);
        EventContextAssertions::assertPrincipal($principal, $refreshed[0]->context);
        EventContextAssertions::assertSession($session, $refreshed[0]->context);
    }

    /**
     * A successful refresh reports `Refreshed` and `SignedIn` before the bind,
     * then `Validated`, `Login` and the bind events.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshDispatchesRefreshedAndSignedInBeforeTheBind(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 19]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '19',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-19');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-19')
            ->andReturn($principal);

        $session->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'principal' => 'p-19',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $dispatched = [];

        $this->events->shouldReceive('dispatch')
            ->times(8)
            ->andReturnUsing(static function (object $event) use (&$dispatched): void {
                $dispatched[] = $event;
            });

        self::assertTrue(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->isRefreshed());
        self::assertSame([
            Attempting::class,
            Refreshed::class,
            SignedIn::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            PrincipalAssigned::class,
            SessionAuthenticated::class,
        ], array_map(static fn (object $event): string => $event::class, $dispatched));

        $refreshed = $dispatched[1];
        $signedIn  = $dispatched[2];

        self::assertInstanceOf(Refreshed::class, $refreshed);
        self::assertInstanceOf(SignedIn::class, $signedIn);
        self::assertSame($refreshed->context, $signedIn->context);
        self::assertTrue($signedIn->refresh);
        self::assertSame('password', $signedIn->context->method);
        EventContextAssertions::assertSession($session, $signedIn->context);
    }

    /**
     * A successful refresh binds the identity, principal and the session row
     * the exchange read under its lock.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshBindsIdentityPrincipalAndSessionOnSuccess(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 7]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '7',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $session->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertTrue(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->isRefreshed());
        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertIsModel($session, $guard->session());
    }

    /**
     * `refresh()` uses a principal resolver rebound on the guard.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshUsesReplacementResolverAfterGuardResolverRebind(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 17]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '17',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($session, $identity);

        $this->swapSessionModelToInMemoryInstance($session);

        $guard = $this->makeGuard($this->makeRequest(null));

        $replacement = \Mockery::mock(PrincipalResolver::class);
        $principal   = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();

        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-17');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $replacement->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $this->resolver->shouldNotReceive('resolve');

        $guard->setPrincipalResolver($replacement);

        $session->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        self::assertTrue(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->isRefreshed());
        self::assertSame($principal, $guard->principal());
    }

    /**
     * `setPrincipalResolver()` also rebinds the resolver bearer resolution
     * reads.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testSetPrincipalResolverUpdatesBearerResolutionPath(): void
    {
        $token = $this->encodeAccessToken(['sub' => 'i-1', 'principal' => 'p-1']);

        $guard = $this->makeGuard($this->makeRequest($token));

        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('i-1');

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')
            ->andReturn('p-1');
        $principal->shouldReceive('isActive')
            ->once()
            ->andReturnTrue();

        $replacement = \Mockery::mock(PrincipalResolver::class);
        $replacement->shouldReceive('resolve')
            ->once()
            ->with($identity, 'p-1')
            ->andReturn($principal);

        $this->resolver->shouldNotReceive('resolve');

        $this->provider->shouldReceive('retrieveById')
            ->once()
            ->with('i-1')
            ->andReturn($identity);

        $this->events->shouldReceive('dispatch')->andReturnNull();

        $guard->setPrincipalResolver($replacement);

        self::assertSame($identity, $guard->user());
        self::assertSame($principal, $guard->principal());
    }

    /**
     * `setDispatcher()` returns the guard and sends later refresh failures to
     * the new dispatcher only.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testSetDispatcherRoutesLaterRefreshFailuresToTheNewDispatcher(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $replacement = \Mockery::mock(Dispatcher::class);
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Attempting::class));
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                && $event->reason === FailureReason::TOKEN_INVALID));
        $replacement->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Failed::class));

        $this->events->shouldNotReceive('dispatch');

        self::assertSame($guard, $guard->setDispatcher($replacement));
        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody('not-a-jwt'), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * Allow the `Attempting` and `Failed` events every failed refresh
     * dispatches, without constraining them.
     *
     * @return void
     */
    private function expectRefreshFailureEvents(): void
    {
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->with(\Mockery::type(Failed::class));
    }
}
