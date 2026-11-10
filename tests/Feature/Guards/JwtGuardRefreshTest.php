<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\Carbon;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the token-level and session-level validation paths within a
 * JWT guard's refresh-token exchange, including rotation integrity checks.
 *
 * Covers token parsing failures, session lookup, replay detection and the grace
 * window, and session revocation. Identity and principal resolution tests live
 * in JwtGuardRefreshResolutionTest.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(IdentifierCoercion::class)]
final class JwtGuardRefreshTest extends JwtGuardTestCase
{
    use InteractsWithSessionRecords;

    /**
     * When the refresh token cannot be parsed, `refresh()` fails and fires
     * `AuthenticationFailed` with reason `token_invalid`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenTokenCannotBeParsed(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::TOKEN_INVALID),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody('not-a-jwt'), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A refresh token without a `sid` claim fails and fires
     * `AuthenticationFailed` with reason `token_invalid`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenSessionIdMissingFromClaims(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken(['jti' => 'some-rotation-id']);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason === FailureReason::TOKEN_INVALID),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * When the session lookup returns null, `refresh()` fails and fires
     * `AuthenticationFailed` with reason `session_unknown`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenSessionLookupFails(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'sid' => '01HZZZZZZZZZZZZZZZZZZZZZZZ',
            'jti' => 'rotation-id',
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason             === FailureReason::SESSION_UNKNOWN
                    && $event->context->sessionId === '01HZZZZZZZZZZZZZZZZZZZZZZZ'),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A refresh token for a live session whose rotation id the session never
     * held as current or previous is a replay: `refresh()` fails, revokes the
     * session, and dispatches `SessionRevoked`, `AuthenticationFailed` with
     * reason `rotation_reuse`, and Laravel's `Failed`.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRevokesTheSessionForARotationIdItDoesNotHold(): void
    {
        $session = new StubSession;
        $session->forceFill([...self::liveSession(self::GUARD_NAME), 'refresh_key' => RefreshTokenHasher::hash('stored-rotation-id')])->save();

        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => 'tampered-rotation-id',
        ]);

        $dispatched = $this->recordDispatchedEvents();

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);

        $events = $dispatched->getArrayCopy();

        $classes = array_map(static fn (object $event): string => $event::class, $events);

        self::assertSame([Attempting::class, SessionRevoked::class, Failed::class, AuthenticationFailed::class], $classes);
        self::assertInstanceOf(AuthenticationFailed::class, $events[3]);
        self::assertSame(FailureReason::ROTATION_REUSE, $events[3]->reason);

        $fresh = StubSession::query()->findOrFail($session->id);

        self::assertNotNull($fresh->revoked_at);
        self::assertSame('rotation_reuse', $fresh->revoked_reason);
        self::assertNull($fresh->refresh_key);
    }

    /**
     * A refresh token whose `jti` is present but empty lacks a required claim,
     * so it fails to parse and yields `token_invalid`; a token that does not
     * parse carries no session id for attribution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenRotationIdClaimIsEmptyString(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'sid' => 'session-empty-jti',
            'jti' => '',
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason             === FailureReason::TOKEN_INVALID
                    && $event->context->sessionId === null),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A refresh token whose `jti` is not a string is malformed and yields
     * `token_invalid` while preserving the parseable session id for
     * attribution.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenRotationIdClaimIsNotString(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $token = $this->encodeRefreshToken([
            'sid' => 'session-non-string-jti',
            'jti' => 12345,
        ]);

        $this->expectRefreshFailureEvents();
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(
                \Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                    && $event->reason             === FailureReason::TOKEN_INVALID
                    && $event->context->sessionId === 'session-non-string-jti'),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A refresh attempt against a session whose `revoked_at` column is set
     * fails and fires `AuthenticationFailed` with reason `session_revoked`,
     * regardless of whether the rotation id verifies against the stored digest.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshReturnsNullWhenSessionHasBeenRevoked(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'refresh_key' => RefreshTokenHasher::hash($plainRotationId),
            'revoked_at'  => Carbon::now(),
        ])->save();

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
                    && $event->reason === FailureReason::SESSION_REVOKED),
            );

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
    }

    /**
     * A digest replaced between the exchange's re-read and its swap, inside its
     * own transaction, by something other than a rotation (no previous digest
     * records the presented id) is judged again from the row as it now is: the
     * presented id is neither current nor previous, so it is a replay and the
     * session is revoked.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshRevokesTheSessionWhenItsDigestIsReplacedBeforeTheSwap(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 13]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '13',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->expectOwnerReload($session, $identity);

        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $session): void {
            if ($ran || !str_contains($query, 'refresh_rotated_at')) {
                return;
            }

            $ran = true;

            DB::table('stub_sessions')->where('id', $session->id)->update(['refresh_key' => RefreshTokenHasher::hash('replaced-elsewhere')]);
        });

        $guard = $this->makeGuard($this->makeRequest(null));

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-13');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->once()
            ->with($identity)
            ->andReturn($principal);

        $session->forceFill(self::recordedPrincipal($principal))->save();

        $token = $this->encodeRefreshToken([
            'sid' => $session->id,
            'jti' => $plainRotationId,
        ]);

        $dispatched = $this->recordDispatchedEvents();

        self::assertNull(GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($token), self::requestClient($guard->getRequest()))->session);
        self::assertContains(SessionRevoked::class, array_map(static fn (object $event): string => $event::class, $dispatched->getArrayCopy()));

        $fresh = StubSession::query()->findOrFail($session->id);

        self::assertSame('rotation_reuse', $fresh->revoked_reason);
        self::assertNull($fresh->refresh_key);
    }

    /**
     * The refresh token a successful refresh replaced still gets the session's
     * current credential inside the grace window, through the guard, with the
     * same events as any refresh; once the window has passed it is a replay and
     * revokes the session.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testReplacedRefreshTokenIsHonoredInsideTheGraceWindowOnly(): void
    {
        $plainRotationId = 'stored-rotation-id';

        $identity = new StubIdentity;
        $identity->forceFill(['id' => 18]);

        $session = new StubSession;
        $session->forceFill([
            ...self::liveSession(self::GUARD_NAME),
            'authenticatable_type' => StubIdentity::class,
            'authenticatable_id'   => '18',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $this->provider->shouldReceive('retrieveById')
            ->twice()
            ->with('18')
            ->andReturn($identity);

        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-18');
        $principal->shouldReceive('isActive')->andReturnTrue();

        $this->resolver->shouldReceive('resolve')
            ->twice()
            ->with($identity, 'p-18')
            ->andReturn($principal);

        $session->forceFill(self::recordedPrincipal($principal))->save();

        $oldToken = $this->encodeRefreshToken([
            'principal' => 'p-18',
            'sid'       => $session->id,
            'jti'       => $plainRotationId,
        ]);

        $dispatched = $this->recordDispatchedEvents();

        $rotated = GuardSessions::of($this->makeGuard($this->makeRequest(null)))->refresh(PresentedRefreshToken::fromBody($oldToken), self::requestClient())->session?->tokens;

        self::assertInstanceOf(TokenPair::class, $rotated);

        Carbon::setTestNow($this->now->copy()->addSeconds(29));

        $retried = GuardSessions::of($this->makeGuard($this->makeRequest(null)))->refresh(PresentedRefreshToken::fromBody($oldToken), self::requestClient())->session?->tokens;

        self::assertInstanceOf(TokenPair::class, $retried);
        self::assertSame(
            $this->tokens->parse(self::bodyRefreshToken($rotated), TokenType::REFRESH)[Claims::JWT_ID->value] ?? null,
            $this->tokens->parse(self::bodyRefreshToken($retried), TokenType::REFRESH)[Claims::JWT_ID->value] ?? null,
        );
        self::assertCount(2, array_filter($dispatched->getArrayCopy(), static fn (object $event): bool => $event instanceof Refreshed));

        Carbon::setTestNow($this->now->copy()->addSeconds(30));

        self::assertNull(GuardSessions::of($this->makeGuard($this->makeRequest(null)))->refresh(PresentedRefreshToken::fromBody($oldToken), self::requestClient())->session);
        self::assertSame('rotation_reuse', StubSession::query()->findOrFail($session->id)->revoked_reason);
    }

    /**
     * A failed refresh dispatches the standard Laravel `Failed` event in
     * addition to the package-specific `AuthenticationFailed`. Mutation guard:
     * pins the `Failed` the refresh dispatches with no user and no credentials.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testRefreshDispatchesFailedEventOnFailure(): void
    {
        $guard = $this->makeGuard($this->makeRequest(null));

        $failedEvent = null;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use (&$failedEvent): void {
                if (!$event instanceof Failed) {
                    return;
                }

                $failedEvent = $event;
            });

        GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody('not-a-jwt'), self::requestClient($guard->getRequest()));

        self::assertInstanceOf(Failed::class, $failedEvent);
        self::assertSame(self::GUARD_NAME, $failedEvent->guard);
        self::assertNull($failedEvent->user);
    }

    /**
     * Allow the standard `Attempting` + `Failed` events that every failed
     * refresh now dispatches (alongside the package-specific
     * `AuthenticationFailed` event). Tests that assert a specific
     * `AuthenticationFailed` reason call this helper first to permit the
     * standard events without constraining them.
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

    /**
     * Record every event the guard and its exchange dispatch.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordDispatchedEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, object> $dispatched */
        $dispatched = new \ArrayObject;

        $this->events->shouldReceive('dispatch')
            ->andReturnUsing(static function (object $event) use ($dispatched): void {
                $dispatched->append($event);
            });

        return $dispatched;
    }
}
