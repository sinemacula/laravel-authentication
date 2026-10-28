<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingFactor;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoice;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;

/**
 * Unit tests for how a sign-in through the session service ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInResult::class)]
#[CoversClass(SignedInSession::class)]
#[CoversClass(PrincipalChoice::class)]
final class SignInResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A started session is signed in and carries the session, no reason and no
     * wait.
     *
     * @return void
     */
    public function testASignedInResultCarriesTheSession(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class);
        $device    = \Mockery::mock(Model::class, EloquentDevice::class);
        $tokens    = new RefreshResult('access', 'refresh');
        $session   = new SignedInSession($identity, $principal, $device, $tokens, 'password', true);
        $result    = SignInResult::signedIn($session);

        self::assertSame(SignInStatus::SIGNED_IN, $result->status);
        self::assertTrue($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertSame($session, $result->session);
        self::assertFalse($result->requiresFactor());
        self::assertNull($result->pending);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);

        self::assertSame($identity, $session->identity);
        self::assertSame($principal, $session->principal);
        self::assertSame($device, $session->device);
        self::assertSame($tokens, $session->tokens);
        self::assertSame('password', $session->method);
        self::assertTrue($session->deviceCreated);
    }

    /**
     * A sign-in that needs a further factor carries the pending sign-in, and
     * neither a session nor a reason.
     *
     * @return void
     */
    public function testAPendingFactorResultCarriesThePendingSignIn(): void
    {
        $pending = new PendingFactor('token', 'api', \Mockery::mock(Identity::class), \Mockery::mock(Principal::class), null, 'password', CarbonImmutable::now(), null);
        $result  = SignInResult::pendingFactor($pending);

        self::assertSame(SignInStatus::FACTOR_REQUIRED, $result->status);
        self::assertTrue($result->requiresFactor());
        self::assertFalse($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertSame($pending, $result->pending);
        self::assertNull($result->session);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertFalse(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->requiresFactor());
    }

    /**
     * A sign-in that waits for a choice of principal carries the choice, and
     * neither a session, a pending factor nor a reason; no other result
     * requires a principal.
     *
     * @return void
     */
    public function testAPrincipalRequiredResultCarriesTheChoice(): void
    {
        $identity   = \Mockery::mock(Identity::class);
        $principals = [\Mockery::mock(Principal::class)];
        $expiresAt  = CarbonImmutable::now();
        $choice     = new PrincipalChoice('token', 'api', $identity, $principals, 'password', $expiresAt);
        $result     = SignInResult::principalRequired($choice);

        self::assertSame(SignInStatus::PRINCIPAL_REQUIRED, $result->status);
        self::assertTrue($result->requiresPrincipal());
        self::assertFalse($result->requiresFactor());
        self::assertFalse($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertSame($choice, $result->choice);
        self::assertNull($result->session);
        self::assertNull($result->pending);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);

        self::assertSame('token', $choice->token);
        self::assertSame('api', $choice->guard);
        self::assertSame($identity, $choice->identity);
        self::assertSame($principals, $choice->principals);
        self::assertSame('password', $choice->method);
        self::assertSame($expiresAt, $choice->expiresAt);

        self::assertFalse(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->requiresPrincipal());
        self::assertNull(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->choice);
    }

    /**
     * A failure carries its reason and, when given, the wait, and no session.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReason(): void
    {
        $limited = SignInResult::failed(FailureReason::RATE_LIMITED, 30);

        self::assertSame(SignInStatus::FAILED, $limited->status);
        self::assertTrue($limited->isFailed());
        self::assertFalse($limited->isSignedIn());
        self::assertNull($limited->session);
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(30, $limited->retryAfter);

        self::assertNull(SignInResult::failed(FailureReason::INVALID_CREDENTIALS)->retryAfter);
    }

    /**
     * A refusal by the account's own limit is answered as invalid credentials
     * with no wait, so the result never reveals that the account exists.
     *
     * @return void
     */
    public function testAnAccountsOwnLimitIsAnsweredAsInvalidCredentials(): void
    {
        $refused = SignInResult::failed(FailureReason::ACCOUNT_RATE_LIMITED, 30);

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertNull($refused->retryAfter);
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(SignInResult::class, '__construct'))->isPrivate());
    }

    /**
     * The statuses' values name how a sign-in ended.
     *
     * @return void
     */
    public function testStatusValues(): void
    {
        $values = array_map(static fn (SignInStatus $status): string => $status->value, SignInStatus::cases());

        self::assertSame(['signed_in', 'factor_required', 'principal_required', 'failed'], $values);
    }
}
