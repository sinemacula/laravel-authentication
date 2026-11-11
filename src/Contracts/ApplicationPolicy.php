<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Decides which sign-in methods and machine credentials an application accepts,
 * which identifiers it admits and how long its sessions last.
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
     * Whether a client credentials exchange may read the client's id and secret
     * from the request body (`client_secret_post`).
     *
     * @param  string  $guard
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    public function allowsClientSecretPost(string $guard): bool;

    /**
     * Decide whether the identity may sign in to the application with an
     * identifier of the type: `null` when it may, otherwise why not.
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
