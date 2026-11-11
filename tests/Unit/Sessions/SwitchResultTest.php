<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use Tests\Fixtures\Proofs\UndescribedSignInProof;

/**
 * Unit tests for how a switch ends: switched, returned to pending, or refused.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SwitchResult::class)]
#[CoversTrait(HoldsARotatedSession::class)]
final class SwitchResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A switch that succeeded carries the session, and no reason or wait.
     *
     * @return void
     */
    public function testASwitchedResultCarriesTheSession(): void
    {
        $record  = \Mockery::mock(Model::class, EloquentSession::class);
        $session = new SignedInSession(
            \Mockery::mock(Identity::class),
            \Mockery::mock(Principal::class),
            $record,
            new TokenPair(new Secret('access'), CarbonImmutable::now()->addMinutes(5), 300, new Secret('refresh')),
            'password',
        );
        $result = SwitchResult::switched($session);

        self::assertTrue($result->isSwitched());
        self::assertFalse($result->isFailed());
        self::assertFalse($result->isPending());
        self::assertSame($session, $result->session);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertNull($result->source);
    }

    /**
     * The same outcome read from a source keeps every part and says which
     * source, without changing the result it came from.
     *
     * @return void
     */
    public function testAResultReadFromASourceSaysWhich(): void
    {
        $limited = SwitchResult::failed(FailureReason::RATE_LIMITED, 30);
        $read    = $limited->withSource(RefreshTokenSource::COOKIE);

        self::assertNotSame($limited, $read);
        self::assertNull($limited->source);
        self::assertSame(RefreshTokenSource::COOKIE, $read->source);
        self::assertSame(FailureReason::RATE_LIMITED, $read->reason);
        self::assertSame(30, $read->retryAfter);

        $record  = \Mockery::mock(Model::class, EloquentSession::class);
        $session = new SignedInSession(
            \Mockery::mock(Identity::class),
            \Mockery::mock(Principal::class),
            $record,
            new TokenPair(new Secret('access'), CarbonImmutable::now()->addMinutes(5), 300, new Secret('refresh')),
            'password',
        );

        self::assertSame($session, SwitchResult::switched($session)->withSource(RefreshTokenSource::BODY)->session);
    }

    /**
     * A refused switch carries its reason and, when given, the wait.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReason(): void
    {
        $limited = SwitchResult::failed(FailureReason::RATE_LIMITED, 30);

        self::assertTrue($limited->isFailed());
        self::assertFalse($limited->isSwitched());
        self::assertNull($limited->session);
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(30, $limited->retryAfter);

        self::assertNull(SwitchResult::failed(FailureReason::PRINCIPAL_MISMATCH)->retryAfter);
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(SwitchResult::class, '__construct'))->isPrivate());
    }

    /**
     * A switch returned to pending carries the pending session and its
     * credential, and is neither switched nor refused.
     *
     * @return void
     */
    public function testAPendingResultCarriesThePendingSessionAndItsCredential(): void
    {
        $pending = new PendingSession(
            'session-key',
            'api',
            \Mockery::mock(Identity::class),
            \Mockery::mock(Principal::class),
            null,
            [PendingRequirement::MFA],
            'password',
            CarbonImmutable::parse('2026-04-06 12:05:00'),
            \Mockery::mock(Session::class),
            new Requirement,
            self::firstFactor(),
        );

        $credential = new Secret('session-key.secret');
        $result     = SwitchResult::pending($pending, $credential);

        self::assertTrue($result->isPending());
        self::assertFalse($result->isSwitched());
        self::assertFalse($result->isFailed());
        self::assertSame($pending, $result->pending);
        self::assertSame($credential, $result->credential);
        self::assertNull($result->session);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);

        $read = $result->withSource(RefreshTokenSource::COOKIE);

        self::assertSame($pending, $read->pending);
        self::assertSame($credential, $read->credential);
        self::assertSame(RefreshTokenSource::COOKIE, $read->source);
    }

    /**
     * The proof of a first factor, as a session records it.
     *
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private static function firstFactor(): RecordedProof
    {
        return UndescribedSignInProof::of('password', CarbonImmutable::now())->recorded();
    }
}
