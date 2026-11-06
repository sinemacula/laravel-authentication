<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Response;

/**
 * How a sign-out ended: whether this call revoked a session, why the refresh
 * credential was refused when it was, where the refresh credential was read
 * from when one was, and, for a cookie application, the expired cookie that
 * clears the browser's when the request came from its own pages.
 *
 * A sign-out is never a failed authentication: a refusal only says why the
 * refresh credential proved no session, and a session it leaves unproven stays
 * live. `signOutWith()` forgets only a binding to the session it revoked, so a
 * guard bound to another session stays bound.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignOutResult
{
    /**
     * Constructor.
     *
     * @param  bool  $signedOut
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $forgetCookie
     */
    private function __construct(

        /** Whether this call revoked a session. */
        public bool $signedOut,

        /** Why the refresh credential was refused, when it was. */
        public ?FailureReason $reason,

        /** Where the refresh credential was read from, when one was. */
        public ?RefreshTokenSource $source,

        /** A cookie application's expired refresh cookie, or `null` for a body application and a request it must not clear for. */
        public ?Cookie $forgetCookie,
    ) {}

    /**
     * A sign-out that revoked a session, proven by a refresh credential read
     * from the source, or by the request's access token when there is none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $forget
     * @return self
     */
    public static function signedOut(?RefreshTokenSource $source, ?Cookie $forget): self
    {
        return new self(true, null, $source, $forget);
    }

    /**
     * A sign-out that found no session to revoke, and no refresh credential to
     * refuse.
     *
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $forget
     * @return self
     */
    public static function nothing(?Cookie $forget): self
    {
        return new self(false, null, null, $forget);
    }

    /**
     * A sign-out whose refresh credential was refused for the reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  ?\Symfony\Component\HttpFoundation\Cookie  $forget
     * @return self
     */
    public static function failed(FailureReason $reason, ?RefreshTokenSource $source, ?Cookie $forget): self
    {
        return new self(false, $reason, $source, $forget);
    }

    /**
     * Whether this call revoked a session.
     *
     * @return bool
     */
    public function isSignedOut(): bool
    {
        return $this->signedOut;
    }

    /**
     * Whether the refresh credential was refused.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->reason !== null;
    }

    /**
     * Add the clearing cookie to the response, when there is one.
     *
     * @template TResponse of \Symfony\Component\HttpFoundation\Response
     *
     * @param  TResponse  $response
     * @return TResponse
     */
    public function attachTo(Response $response): Response
    {
        if ($this->forgetCookie !== null) {
            $response->headers->setCookie($this->forgetCookie);
        }

        return $response;
    }
}
