<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Audience policy contract.
 *
 * An audience is a guard: each guard decides which sign-in methods may start
 * its sessions, which principals may hold them, whether the identifier a
 * sign-in used must be verified, and how long its sessions and tokens last for
 * each principal type. The session service consults it before it issues
 * anything, and the refresh exchange before it rotates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AudiencePolicy
{
    /**
     * Whether the guard lets the sign-in method start its sessions.
     *
     * @param  string  $guard
     * @param  string  $method
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function allowsMethod(string $guard, string $method): bool;

    /**
     * Decide whether the identity may hold a session of the guard as the
     * principal: `null` when it may, otherwise why not. The caller has already
     * checked that the identity, the principal and its tenant are active. An
     * identifier type of `null` (a sign-in that used no identifier, or a
     * refresh) is not subject to the verified-identifier requirement. A
     * principal choice lists, and a switch of principal reaches, only the
     * principals admitted with the type the session's sign-in used.
     *
     * A policy may refuse some principals to an identifier of a type and admit
     * others. It is asked only once a principal resolves, though, so an
     * identity with none fails as `principal_unresolved` whatever its
     * identifier: decide verification for the identity as a whole where the
     * difference must not show (the package's policy refuses an unverified
     * identifier before any principal is resolved).
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function admit(string $guard, Identity $identity, Principal $principal, ?string $identifierType): ?FailureReason;

    /**
     * The token and session lifetimes of the guard for the principal's type.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     *
     * @throws \InvalidArgumentException
     */
    public function lifetimes(string $guard, Principal $principal): TokenLifetimes;
}
