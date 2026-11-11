<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * The `auth_time` and `amr` a session's access token carries, derived from the
 * session's proofs when the token is issued.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthenticationClaims
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The session's authentication time and `amr` values, read current unless
     * `$current` is `false`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary
     *
     * @throws \LogicException
     */
    public static function forSession(Session $session, bool $current = true): AuthenticationSummary
    {
        $history = SessionProofs::history($session, $current);
        $at      = $history->authenticatedAt();

        if ($at === null || !$history->hasFirstFactor()) {
            throw new \LogicException('The session records no counting first factor, so no access token can say when or how it authenticated.');
        }

        return new AuthenticationSummary($at, $history->methods());
    }
}
