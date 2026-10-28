<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\CodeRequest;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;

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
     * A sent request carries when its code expires and no wait.
     *
     * @return void
     */
    public function testASentRequestCarriesTheExpiry(): void
    {
        $expiresAt = CarbonImmutable::createStrict(2026, 4, 6, 12, 10, 0);
        $request   = CodeRequest::sent($expiresAt);

        self::assertSame([CodeRequestStatus::SENT, $expiresAt, null], [$request->status, $request->expiresAt, $request->retryAfter]);
        self::assertTrue($request->isSent());
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
