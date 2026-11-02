<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Sessions\SignOutResult;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * Unit tests for how a sign-out ends: whether it revoked a session, why its
 * refresh credential was refused, where that credential was read from, and the
 * cookie that clears a cookie application's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignOutResult::class)]
final class SignOutResultTest extends TestCase
{
    /**
     * A sign-out that revoked a session is signed out and not failed, with no
     * reason, and keeps the source and the cookie it was given.
     *
     * @return void
     */
    public function testASignedOutResultRevokedASession(): void
    {
        $forget = self::forgetCookie();
        $result = SignOutResult::signedOut(RefreshTokenSource::COOKIE, $forget);

        self::assertTrue($result->isSignedOut());
        self::assertTrue($result->signedOut);
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertSame(RefreshTokenSource::COOKIE, $result->source);
        self::assertSame($forget, $result->forgetCookie);

        $bearer = SignOutResult::signedOut(null, null);

        self::assertTrue($bearer->isSignedOut());
        self::assertNull($bearer->source);
        self::assertNull($bearer->forgetCookie);
    }

    /**
     * A sign-out that found nothing to revoke is neither signed out nor failed,
     * and has no reason or source.
     *
     * @return void
     */
    public function testANothingResultRevokedNothingAndRefusedNothing(): void
    {
        $forget = self::forgetCookie();
        $result = SignOutResult::nothing($forget);

        self::assertFalse($result->isSignedOut());
        self::assertFalse($result->signedOut);
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertNull($result->source);
        self::assertSame($forget, $result->forgetCookie);
    }

    /**
     * A refused refresh credential fails with its reason and its source, and
     * revoked nothing.
     *
     * @return void
     */
    public function testAFailedResultCarriesTheReasonAndTheSource(): void
    {
        $result = SignOutResult::failed(FailureReason::ROTATION_REUSE, RefreshTokenSource::HEADER, null);

        self::assertTrue($result->isFailed());
        self::assertFalse($result->isSignedOut());
        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame(RefreshTokenSource::HEADER, $result->source);
        self::assertNull($result->forgetCookie);
    }

    /**
     * Attaching adds the clearing cookie to the response and returns that same
     * response; without a cookie the response is returned untouched.
     *
     * @return void
     */
    public function testAttachingAddsTheClearingCookieWhenThereIsOne(): void
    {
        $forget   = self::forgetCookie();
        $response = new Response;

        self::assertSame($response, SignOutResult::failed(FailureReason::CROSS_SITE_REQUEST, null, $forget)->attachTo($response));
        self::assertSame([$forget], $response->headers->getCookies());

        $plain = new Response;

        self::assertSame($plain, SignOutResult::signedOut(RefreshTokenSource::BODY, null)->attachTo($plain));
        self::assertSame([], $plain->headers->getCookies());
    }

    /**
     * An expired refresh cookie, as a cookie application's transport forgets
     * it.
     *
     * @return \Symfony\Component\HttpFoundation\Cookie
     */
    private static function forgetCookie(): Cookie
    {
        return Cookie::create('__Secure-browser_refresh_token', null, 1, '/auth', null, true, true, false, Cookie::SAMESITE_STRICT);
    }
}
