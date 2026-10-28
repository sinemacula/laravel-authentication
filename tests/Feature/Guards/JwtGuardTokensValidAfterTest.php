<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\CarbonInterface;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;

/**
 * Feature tests for the "tokens valid after" time on the bearer path: an access
 * token issued without a device is rejected as `issued_before_cutoff` when it
 * was issued at or before the time its identity or its principal records, and a
 * token that names a device is never held to it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
#[CoversClass(JwtGuard::class)]
final class JwtGuardTokensValidAfterTest extends JwtGuardTestCase
{
    /**
     * Rows of `[seconds from the token's iat to the cutoff, accepted]`. The
     * cutoff is whole seconds, so a token issued in its very second is
     * rejected.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideCutoffs(): iterable
    {
        yield 'cutoff a second before issue' => [-1, true];
        yield 'cutoff in the issue second' => [0, false];
        yield 'cutoff a second after issue' => [1, false];
    }

    /**
     * The identity's time is held against the token's `iat`.
     *
     * @param  int  $offset
     * @param  bool  $accepted
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideCutoffs')]
    public function testTheIdentitysTimeLimitsADevicelessToken(int $offset, bool $accepted): void
    {
        $identity  = $this->identity($this->now->copy()->addSeconds($offset));
        $principal = $this->principal(null);

        $this->expectOutcome($accepted);

        self::assertSame($accepted ? $identity : null, $this->guardFor($identity, $principal)->user());
    }

    /**
     * The principal's time is held against the token's `iat` too.
     *
     * @param  int  $offset
     * @param  bool  $accepted
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[DataProvider('provideCutoffs')]
    public function testThePrincipalsTimeLimitsADevicelessToken(int $offset, bool $accepted): void
    {
        $identity  = $this->identity(null);
        $principal = $this->principal($this->now->copy()->addSeconds($offset));

        $this->expectOutcome($accepted);

        self::assertSame($accepted ? $identity : null, $this->guardFor($identity, $principal)->user());
    }

    /**
     * An identity and a principal that record no time, or do not record one at
     * all, do not limit the token.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testNoTimeDoesNotLimitTheToken(): void
    {
        $identity  = $this->identity(null);
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $principal->shouldReceive('getTenant')->andReturnNull();

        $this->expectOutcome(true);

        self::assertSame($identity, $this->guardFor($identity, $principal)->user());
    }

    /**
     * A token whose `iat` is not a whole number of seconds is rejected when a
     * time is recorded, since it cannot be placed after it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testATokenWithoutAWholeIssueTimeIsRejectedAgainstATime(): void
    {
        $identity = $this->identity($this->now->copy()->subDay());

        $this->expectOutcome(false);

        $token = $this->encodeToken([
            'jti' => 'access-token-id',
            'sub' => 'i-1',
            'pid' => 'p-1',
            'iat' => $this->now->getTimestamp() - 0.5,
            'exp' => $this->now->getTimestamp() + 900,
            'typ' => 'access',
            'grd' => self::GUARD_NAME,
        ]);

        self::assertNull($this->guardFor($identity, $this->principal(null), $token)->user());
    }

    /**
     * The failure carries the identity and principal the token named.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testTheFailureCarriesTheContext(): void
    {
        $identity  = $this->identity($this->now);
        $principal = $this->principal(null);
        $failure   = null;

        $this->events->shouldReceive('dispatch')
            ->once()
            ->andReturnUsing(static function (object $event) use (&$failure): void {
                $failure = $event;
            });

        self::assertNull($this->guardFor($identity, $principal)->user());
        self::assertInstanceOf(AuthenticationFailed::class, $failure);
        self::assertSame($identity, $failure->context->identity);
        self::assertSame($principal, $failure->context->principal);
        self::assertNull($failure->context->device);
    }

    /**
     * An identity whose time was not loaded fails closed: its `LogicException`
     * propagates rather than reading as no time.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testATimeThatWasNotLoadedIsReported(): void
    {
        $identity = \Mockery::mock(Identity::class, HasTokensValidAfter::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('i-1');
        $identity->shouldReceive('getTokensValidAfter')->andThrow(new \LogicException('tokens_valid_after is not loaded'));

        $this->events->shouldNotReceive('dispatch');

        $this->expectException(\LogicException::class);

        $this->guardFor($identity, $this->principal(null))->user();
    }

    /**
     * Expect the request's token to be accepted (the bind events) or rejected
     * as `issued_before_cutoff` (one failure and nothing else).
     *
     * @param  bool  $accepted
     * @return void
     */
    private function expectOutcome(bool $accepted): void
    {
        if ($accepted) {
            $this->events->shouldReceive('dispatch')->with(\Mockery::not(\Mockery::type(AuthenticationFailed::class)));

            return;
        }

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof AuthenticationFailed
                && $event->flow   === AuthenticationFlow::BEARER
                && $event->reason === FailureReason::ISSUED_BEFORE_CUTOFF));
    }

    /**
     * A guard serving a device-less token for the identity and principal, or
     * the given token.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function guardFor(Identity $identity, Principal $principal, ?string $token = null): JwtGuard
    {
        $this->provider->shouldReceive('retrieveById')->once()->with('i-1')->andReturn($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity, 'p-1')->andReturn($principal);

        return $this->makeGuard($this->makeRequest($token ?? $this->encodeAccessToken(['sub' => 'i-1', 'pid' => 'p-1'])));
    }

    /**
     * An identity that records the given time.
     *
     * @param  ?\Carbon\CarbonInterface  $time
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(?CarbonInterface $time): MockInterface
    {
        $identity = \Mockery::mock(Identity::class, HasTokensValidAfter::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('i-1');
        $identity->shouldReceive('getTokensValidAfter')->andReturn($time);

        return $identity;
    }

    /**
     * A principal, acting within no tenant, that records the given time.
     *
     * @param  ?\Carbon\CarbonInterface  $time
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principal(?CarbonInterface $time): MockInterface
    {
        $principal = \Mockery::mock(Principal::class, HasTokensValidAfter::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');
        $principal->shouldReceive('getTenant')->andReturnNull();
        $principal->shouldReceive('getTokensValidAfter')->andReturn($time);

        return $principal;
    }
}
