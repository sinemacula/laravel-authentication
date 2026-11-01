<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * The outcome of stepping a session up or reauthenticating it: a new access
 * token for the same session, which keeps its refresh token and deadlines, or
 * why none was issued.
 *
 * A concealed reason (an account's own limit, an expired or exhausted code, a
 * passkey's sign counter that did not advance) is answered as
 * `invalid_credentials`, with no wait, as a sign-in's is; only the server-side
 * `AuthenticationFailed` says why. `retryAfter` carries the wait of a
 * `rate_limited` refusal.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AccessTokenResult
{
    /**
     * Constructor.
     *
     * @param  ?string  $accessToken
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null  $session
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     */
    private function __construct(

        /** The new access token, when one was issued. */
        #[\SensitiveParameter] public ?string $accessToken = null,

        /** The session it was issued for, when one was. */
        public (EloquentSession&Model)|null $session = null,

        /** When the new access token expires, when one was issued. */
        public ?CarbonImmutable $expiresAt = null,

        /** Why no token was issued, when none was. */
        public ?FailureReason $reason = null,

        /** Seconds until another attempt may be made, for `rate_limited` only. */
        public ?int $retryAfter = null,
    ) {}

    /**
     * A new access token for the session, expiring when given.
     *
     * @param  string  $accessToken
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @return self
     */
    public static function issued(#[\SensitiveParameter] string $accessToken, EloquentSession&Model $session, CarbonImmutable $expiresAt): self
    {
        return new self($accessToken, $session, $expiresAt);
    }

    /**
     * No token, and why; a concealed reason is answered as
     * `invalid_credentials`, with no wait.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?int  $retryAfter
     * @return self
     */
    public static function failed(FailureReason $reason, ?int $retryAfter = null): self
    {
        return $reason->isConcealed()
            ? new self(reason: FailureReason::INVALID_CREDENTIALS)
            : new self(reason: $reason, retryAfter: $retryAfter);
    }

    /**
     * Whether a new access token was issued.
     *
     * @return bool
     */
    public function isIssued(): bool
    {
        return $this->accessToken !== null;
    }

    /**
     * Whether no token was issued.
     *
     * @return bool
     */
    public function isFailed(): bool
    {
        return $this->accessToken === null;
    }
}
