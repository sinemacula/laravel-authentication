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
 * accepts, whether the identifier a sign-in used must be verified, and how long
 * its sessions last. The session service consults it before it issues anything,
 * and the refresh exchange before it rotates. Every method takes the
 * application by its guard's name. Which principals may use the application is
 * not the policy's question but `ApplicationAccess`'s, and which tenants they
 * may act in `TenantAccess`'s.
 *
 * The package asks `admitIdentifier()` inside `WriteConnection::during()` for
 * the identity, so a model read the policy makes there, and a query-builder
 * read on the identity's connection, sees the primary rather than a replica
 * that may lag behind a withdrawn verification. Any other read that decides
 * admission (a query-builder read on another connection, or one made from
 * `allowsMethod()`) pins itself with `WriteConnection::query()`.
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
     * a switch asks it with the type the session's sign-in used, so a refusal
     * here is the same whether the identity has principals or not and says
     * nothing about which it has. An identifier type of `null` (a sign-in that
     * used no identifier) is not subject to the verified-identifier
     * requirement. A policy with no rule about the identity as a whole returns
     * `null`; one that wraps another asks it.
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
