<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Application policy contract.
 *
 * An application is a guard: each decides which sign-in methods may start its
 * sessions and which machine credentials (`api_key`, `client_credentials`) it
 * accepts, whether the identifier a sign-in used must be verified, which
 * principals may hold its sessions, and how long its sessions last. The session
 * service consults it before it issues anything, and the refresh exchange
 * before it rotates. Every method takes the application by its guard's name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ApplicationPolicy
{
    /**
     * Whether the application (its guard) lets the sign-in method start its
     * sessions, or accepts the machine credential.
     *
     * @param  string  $guard
     * @param  string  $method
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function allowsMethod(string $guard, string $method): bool;

    /**
     * Decide whether the identity may sign in to the application with an
     * identifier of the type, whichever principal it then acts as: `null` when
     * it may, otherwise why not (`identifier_unverified` for an identifier the
     * application requires verified). Every sign-in asks it once the identity
     * is known to be active and before any principal is resolved or listed, and
     * a switch of principal asks it with the type the session's sign-in used
     * before `admit()`, so a refusal here is the same whether the identity has
     * principals or not and says nothing about which it has. An identifier type
     * of `null` (a sign-in that used no identifier) is not subject to the
     * verified-identifier requirement. A policy with no rule about the identity
     * as a whole returns `null`; one that wraps another asks it.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function admitIdentifier(string $guard, Identity $identity, ?string $identifierType): ?FailureReason;

    /**
     * Decide whether the identity may hold a session of the application as the
     * principal: `null` when it may, otherwise why not (an application that
     * keeps some principals out refuses them here, which a refresh, a switch,
     * an API key and a client credentials exchange report as
     * `principal_ineligible`). The caller has already checked that the
     * identity, the principal and its tenant are active. An identifier type of
     * `null` (a sign-in that used no identifier, or a refresh) is not subject
     * to the verified-identifier requirement. A principal choice lists, and a
     * switch of principal reaches, only the principals admitted with the type
     * the session's sign-in used.
     *
     * A policy may refuse some principals to an identifier of a type and admit
     * others. It is asked only once a principal resolves, though, so an
     * identity with none fails as `principal_unresolved` whatever its
     * identifier: decide verification for the identity as a whole in
     * `admitIdentifier()` where the difference must not show.
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
     * The token and session lifetimes of the application (its guard), which a
     * session's idle and absolute deadlines follow.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     *
     * @throws \InvalidArgumentException
     */
    public function lifetimes(string $guard): TokenLifetimes;
}
