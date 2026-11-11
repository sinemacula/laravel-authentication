<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;

/**
 * Where a session stands: its status, pending state, tenant and principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SessionStanding
{
    /**
     * Return whether the session is active or pending.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus
     *
     * @throws \LogicException
     */
    public function getStatus(): SessionStatus;

    /**
     * Return what a pending session waits on, in the order it must be met;
     * empty for an active session.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>
     *
     * @throws \LogicException
     */
    public function getRequires(): array;

    /**
     * Return the digest, never the plaintext, of a pending session's credential
     * secret, or `null` for an active session.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPendingKey(): ?string;

    /**
     * Return the opaque id of the session's active tenant, or `null` when it
     * acts in none.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getTenantId(): ?string;

    /**
     * Return the stored morph class or class name of the session's principal,
     * or `null` while it acts as none.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPrincipalType(): ?string;

    /**
     * Return the stored id of the session's principal, or `null` while it acts
     * as none.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPrincipalId(): ?string;

    /**
     * Return the version of the tenant authentication policy the session was
     * last checked against, or `null` when the policy answered none.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getTenantPolicyVersion(): ?string;
}
