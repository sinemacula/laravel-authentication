<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;

/**
 * Unit tests for the result of a step-up or a reauthentication: an issued token
 * with its session and expiry, or a refusal, a concealed reason answered as
 * `invalid_credentials` with no wait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccessTokenResult::class)]
final class AccessTokenResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * An issued result carries the token, the session and the expiry, and no
     * reason or wait.
     *
     * @return void
     */
    public function testAnIssuedResultCarriesTheToken(): void
    {
        $session = \Mockery::mock(Model::class, EloquentSession::class);
        $expires = CarbonImmutable::parse('2026-04-06 12:15:00');
        $token   = new Secret('access');
        $result  = AccessTokenResult::issued($token, $session, $expires);

        self::assertTrue($result->isIssued());
        self::assertFalse($result->isFailed());
        self::assertSame([$token, $session, $expires, null, null], [$result->accessToken, $result->session, $result->expiresAt, $result->reason, $result->retryAfter]);
    }

    /**
     * A refusal carries its reason and wait, and no token.
     *
     * @return void
     */
    public function testARefusalCarriesItsReason(): void
    {
        $result = AccessTokenResult::failed(FailureReason::RATE_LIMITED, 60);

        self::assertTrue($result->isFailed());
        self::assertFalse($result->isIssued());
        self::assertSame([null, null, null, FailureReason::RATE_LIMITED, 60], [$result->accessToken, $result->session, $result->expiresAt, $result->reason, $result->retryAfter]);
    }

    /**
     * A concealed reason is answered as `invalid_credentials`, with no wait.
     *
     * @return void
     */
    public function testAConcealedReasonIsAnsweredAsInvalidCredentials(): void
    {
        $result = AccessTokenResult::failed(FailureReason::ACCOUNT_RATE_LIMITED, 300);

        self::assertSame([FailureReason::INVALID_CREDENTIALS, null], [$result->reason, $result->retryAfter]);
    }
}
