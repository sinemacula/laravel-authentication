<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;

/**
 * Unit tests for the result of a request for a one-time code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeRequest::class)]
final class CodeRequestTest extends TestCase
{
    /**
     * A sent request carries its expiry, resend time and challenge, and no
     * wait.
     *
     * @return void
     */
    public function testASentRequestCarriesTheExpiryAndTheChallenge(): void
    {
        $expiresAt = CarbonImmutable::createStrict(2026, 4, 6, 12, 10, 0);
        $resendAt  = CarbonImmutable::createStrict(2026, 4, 6, 12, 1, 0);
        $request   = CodeRequest::sent($expiresAt, $resendAt, 'challenge-1');
        $link      = CodeRequest::sent($expiresAt, $resendAt);

        self::assertSame([CodeRequestStatus::SENT, $expiresAt, null, 'challenge-1'], [$request->status, $request->expiresAt, $request->retryAfter, $request->challengeId]);
        self::assertSame([null, null], [$request->lockedUntil, $request->refusal]);
        self::assertSame($resendAt, $request->resendAvailableAt);
        self::assertSame([null, $resendAt], [$link->challengeId, $link->resendAvailableAt]);
        self::assertTrue($request->isSent());
    }

    /**
     * A request out of deliveries for its window carries the wait until the
     * window ends, and nothing else.
     *
     * @return void
     */
    public function testARequestOutOfDeliveriesCarriesTheWait(): void
    {
        $request = CodeRequest::deliveriesExhausted(900);

        self::assertSame([CodeRequestStatus::DELIVERIES_EXHAUSTED, null, 900, null], [$request->status, $request->expiresAt, $request->retryAfter, $request->challengeId]);
        self::assertNull($request->resendAvailableAt);
        self::assertFalse($request->isSent());
    }

    /**
     * A request the factor package locks carries until when, when it said; one
     * it refuses carries why.
     *
     * @return void
     */
    public function testAFactorPackagesAnswerIsCarried(): void
    {
        $until   = CarbonImmutable::createStrict(2026, 4, 6, 12, 15, 0);
        $locked  = CodeRequest::locked($until);
        $refused = CodeRequest::refused(FactorCodeRefusal::NO_FACTOR);

        self::assertSame([CodeRequestStatus::LOCKED, $until, null, null], [$locked->status, $locked->lockedUntil, $locked->refusal, $locked->retryAfter]);
        self::assertNull(CodeRequest::locked(null)->lockedUntil);
        self::assertSame([CodeRequestStatus::REFUSED, null, FactorCodeRefusal::NO_FACTOR], [$refused->status, $refused->lockedUntil, $refused->refusal]);
        self::assertFalse($locked->isSent());
        self::assertFalse($refused->isSent());
    }

    /**
     * A rate-limited request carries the wait and no expiry.
     *
     * @return void
     */
    public function testARateLimitedRequestCarriesTheWait(): void
    {
        $request = CodeRequest::rateLimited(42);

        self::assertSame([CodeRequestStatus::RATE_LIMITED, null, 42], [$request->status, $request->expiresAt, $request->retryAfter]);
        self::assertFalse($request->isSent());
    }

    /**
     * A refused request carries its status and nothing else.
     *
     * @return void
     */
    public function testARefusedRequestCarriesOnlyItsStatus(): void
    {
        $method     = CodeRequest::methodNotAllowed();
        $identifier = CodeRequest::identifierInvalid();

        self::assertSame([CodeRequestStatus::METHOD_NOT_ALLOWED, null, null], [$method->status, $method->expiresAt, $method->retryAfter]);
        self::assertSame([CodeRequestStatus::IDENTIFIER_INVALID, null, null], [$identifier->status, $identifier->expiresAt, $identifier->retryAfter]);
        self::assertFalse($method->isSent());
        self::assertFalse($identifier->isSent());
    }
}
