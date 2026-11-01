<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * The seam the token service asks for a session's `auth_time` and `amr`.
 *
 * Derived from the session's first-factor sign-in: the time it signed in, and
 * the reference value of the sign-in method that started it (`pwd` for a
 * password, `otp` for an email code, `sms` for a phone code, `pop` for a
 * passkey), none for any other method.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthenticationClaims
{
    /** @var array<string, list<string>> The method references of each package sign-in method. */
    private const array METHODS = [
        'password'   => ['pwd'],
        'email_code' => ['otp'],
        'phone_code' => ['sms'],
        'passkey'    => ['pop'],
    ];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The session's authentication time and method references, refusing a
     * session that records no sign-in time rather than issuing a token with no
     * authentication time.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary
     *
     * @throws \LogicException
     */
    public static function forSession(Session $session): AuthenticationSummary
    {
        $signedInAt = $session->getSignedInAt() ?? throw new \LogicException('Cannot derive the authentication of a session that records no sign-in time.');

        return new AuthenticationSummary(CarbonImmutable::instance($signedInAt)->startOfSecond(), self::METHODS[(string) $session->getSignInMethod()] ?? []);
    }
}
