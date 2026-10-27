<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;
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
     * A failure carries its reason and, when given, the wait, and no session.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReason(): void
    {
        $limited = SignInResult::failed(SignInFailureReason::RATE_LIMITED, 30);

        self::assertSame(SignInStatus::FAILED, $limited->status);
        self::assertTrue($limited->isFailed());
        self::assertFalse($limited->isSignedIn());
        self::assertNull($limited->session);
        self::assertSame(SignInFailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(30, $limited->retryAfter);

        self::assertNull(SignInResult::failed(SignInFailureReason::INVALID_CREDENTIALS)->retryAfter);
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
        self::assertSame(['signed_in', 'failed'], array_map(static fn (SignInStatus $status): string => $status->value, SignInStatus::cases()));
    }
}
