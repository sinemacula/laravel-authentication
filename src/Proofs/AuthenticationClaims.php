<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use SineMacula\Laravel\Authentication\Contracts\Session;

/**
 * The `auth_time` and `amr` an access token of a session carries, derived from
 * the session's proofs when the token is issued (see `ProofHistory`), never
 * stored in their place: the token service calls it for every access token it
 * issues for a session.
 *
 * The proofs are read in one aggregate query on the write connection, bounded
 * by the distinct kinds and `amr` sets the session recorded however long it
 * lives, so a session with many step-ups costs what one with a few does. Inside
 * the transaction that writes a proof, the read sees it.
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
     * The session's authentication time and `amr` values. A session the package
     * wrote always has a counting first factor, so one without is a
     * `LogicException`: no token is issued with no authentication time.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary
     *
     * @throws \LogicException
     */
    public static function forSession(Session $session): AuthenticationSummary
    {
        $history = SessionProofs::history($session);
        $at      = $history->authenticatedAt();

        if ($at === null || !$history->hasFirstFactor()) {
            throw new \LogicException('The session records no counting first factor, so no access token can say when or how it authenticated.');
        }

        return new AuthenticationSummary($at, $history->methods());
    }
}
