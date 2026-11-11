<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Default Eloquent-backed accessors for a session's standing: its status, its
 * pending state, its active tenant and its principal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\EloquentSession
 */
trait RecordsSessionStanding
{
    /**
     * Return whether the session is active or pending.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus
     *
     * @throws \LogicException
     */
    public function getStatus(): SessionStatus
    {
        $value  = $this->loadedSessionAttribute($this->getStatusName(), 'getStatusName');
        $status = is_string($value) ? SessionStatus::tryFrom($value) : null;

        return $status ?? throw new \LogicException(sprintf('The session status of %s is not one the package knows.', static::class));
    }

    /**
     * Column name holding whether the session is active or pending.
     *
     * @return string
     */
    public function getStatusName(): string
    {
        return 'status';
    }

    /**
     * Return what a pending session waits on, in order; empty when it waits on
     * nothing.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>
     *
     * @throws \LogicException
     */
    public function getRequires(): array
    {
        $value = $this->loadedSessionAttribute($this->getRequiresName(), 'getRequiresName');

        if ($value === null) {
            return [];
        }

        $list     = is_string($value) ? json_decode($value, true) : $value;
        $requires = is_array($list) && array_is_list($list) ? array_map(self::requirementOf(...), $list) : [null];

        if (in_array(null, $requires, true)) {
            throw new \LogicException(sprintf('The requirements of %s are not a list the package knows.', static::class));
        }

        /** @var list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement> $requires */
        return $requires;
    }

    /**
     * Column name holding what a pending session waits on.
     *
     * @return string
     */
    public function getRequiresName(): string
    {
        return 'requires';
    }

    /**
     * Return the digest of a pending session's credential secret, or `null`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPendingKey(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute($this->getPendingKeyName(), 'getPendingKeyName'));
    }

    /**
     * Column name holding the digest of a pending session's credential secret.
     *
     * @return string
     */
    public function getPendingKeyName(): string
    {
        return 'pending_key';
    }

    /**
     * Column name holding the session a pending session's sign-in client proved
     * it holds.
     *
     * @return string
     */
    public function getSupersedesSessionIdName(): string
    {
        return 'supersedes_session_id';
    }

    /**
     * Column name holding the refresh digest that session was proven against.
     *
     * @return string
     */
    public function getSupersedesRefreshKeyName(): string
    {
        return 'supersedes_refresh_key';
    }

    /**
     * Column name holding the attempt-limit slots a pending session holds.
     *
     * @return string
     */
    public function getAttemptWindowsName(): string
    {
        return 'attempt_windows';
    }

    /**
     * Return the opaque id of the session's active tenant, or `null`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getTenantId(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute($this->getTenantIdName(), 'getTenantIdName'));
    }

    /**
     * Column name holding the opaque id of the session's active tenant.
     *
     * @return string
     */
    public function getTenantIdName(): string
    {
        return 'tenant_id';
    }

    /**
     * Return the stored type of the principal the session acts as, or `null`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPrincipalType(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute(PrincipalReference::columns($this)[0], 'principal'));
    }

    /**
     * Return the stored id of the principal the session acts as, or `null`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPrincipalId(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute(PrincipalReference::columns($this)[1], 'principal'));
    }

    /**
     * Return the tenant authentication policy version the session was last
     * checked against, or `null`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getTenantPolicyVersion(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute($this->getTenantPolicyVersionName(), 'getTenantPolicyVersionName'));
    }

    /**
     * Column name holding the tenant authentication policy version the session
     * was last checked against.
     *
     * @return string
     */
    public function getTenantPolicyVersionName(): string
    {
        return 'tenant_policy_version';
    }

    /**
     * The requirement a stored value names, or `null` when it names none.
     *
     * @param  mixed  $value
     * @return ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement
     */
    private static function requirementOf(mixed $value): ?PendingRequirement
    {
        return is_string($value) ? PendingRequirement::tryFrom($value) : null;
    }
}
