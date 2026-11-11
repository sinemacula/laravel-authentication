<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * The column-name accessors of an Eloquent session for where it stands.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EloquentSessionStanding
{
    /**
     * Column name holding whether the session is active or pending.
     *
     * @return string
     */
    public function getStatusName(): string;

    /**
     * Column name holding what a pending session waits on.
     *
     * @return string
     */
    public function getRequiresName(): string;

    /**
     * Column name holding the digest of a pending session's credential secret.
     *
     * @return string
     */
    public function getPendingKeyName(): string;

    /**
     * Column name holding the session a pending session's sign-in client proved
     * it holds, which its first activation supersedes.
     *
     * @return string
     */
    public function getSupersedesSessionIdName(): string;

    /**
     * Column name holding the refresh digest that session was proven against.
     *
     * @return string
     */
    public function getSupersedesRefreshKeyName(): string;

    /**
     * Column name holding the attempt-limit slots a pending session's sign-in
     * holds until it first activates.
     *
     * @return string
     */
    public function getAttemptWindowsName(): string;

    /**
     * Column name holding the opaque id of the session's active tenant.
     *
     * @return string
     */
    public function getTenantIdName(): string;

    /**
     * Column name holding the tenant authentication policy version the session
     * was last checked against.
     *
     * @return string
     */
    public function getTenantPolicyVersionName(): string;
}
