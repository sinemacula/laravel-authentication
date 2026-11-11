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
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Fixtures\Proofs\UndescribedSignInProof;

/**
 * Unit tests for how a refresh ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshResult::class)]
#[CoversTrait(HoldsARotatedSession::class)]
final class RefreshResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A refresh that succeeded carries the session, and no reason, wait or
     * source.
     *
     * @return void
     */
    public function testARefreshedResultCarriesTheSession(): void
    {
        $session = self::session();
        $result  = RefreshResult::refreshed($session);

        self::assertTrue($result->isRefreshed());
        self::assertFalse($result->isFailed());
        self::assertSame($session, $result->session);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertNull($result->source);
    }

    /**
     * A refreshed outcome read from a source keeps its session and says which
     * source.
     *
     * @return void
     */
    public function testARefreshReadFromASourceKeepsItsSession(): void
    {
        $session   = self::session();
        $refreshed = RefreshResult::refreshed($session)->withSource(RefreshTokenSource::BODY);

        self::assertSame($session, $refreshed->session);
        self::assertSame(RefreshTokenSource::BODY, $refreshed->source);
        self::assertTrue($refreshed->isRefreshed());
    }

    /**
     * A refresh short of a further factor returns the session to pending with
     * its credential.
     *
     * @return void
     */
    public function testAPendingResultCarriesThePendingSessionAndItsCredential(): void
    {
        $pending = new PendingSession(
            'session-1',
            'api',
            \Mockery::mock(Identity::class),
            null,
            null,
            [PendingRequirement::MFA],
            'password',
            CarbonImmutable::now(),
            \Mockery::mock(Session::class),
            new Requirement,
            self::firstFactor(),
        );
        $credential = new Secret('session-1.secret');
        $returned   = RefreshResult::pending($pending, $credential);
        $read       = $returned->withSource(RefreshTokenSource::COOKIE);

        foreach ([$returned, $read] as $result) {
            self::assertTrue($result->isPending());
            self::assertFalse($result->isRefreshed());
            self::assertFalse($result->isFailed());
            self::assertSame($pending, $result->pending);
            self::assertSame($credential, $result->credential);
            self::assertNull($result->session);
            self::assertNull($result->reason);
        }

        self::assertSame(RefreshTokenSource::COOKIE, $read->source);
        self::assertFalse(RefreshResult::refreshed(self::session())->isPending());
        self::assertNull(RefreshResult::refreshed(self::session())->credential);
        self::assertTrue(RefreshResult::failed(FailureReason::SESSION_PENDING)->isFailed());
        self::assertFalse(RefreshResult::failed(FailureReason::SESSION_PENDING)->isPending());
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(RefreshResult::class, '__construct'))->isPrivate());
    }

    /**
     * A refreshed session with a record of its own.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private static function session(): SignedInSession
    {
        $record = \Mockery::mock(Model::class, EloquentSession::class);

        return new SignedInSession(
            \Mockery::mock(Identity::class),
            \Mockery::mock(Principal::class),
            $record,
            new TokenPair(new Secret('access'), CarbonImmutable::now()->addMinutes(5), 300, new Secret('refresh')),
            'password',
        );
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
