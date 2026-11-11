<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonInterface;

/**
 * Default Eloquent-backed `Session` accessors using conventional attribute
 * names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait ActsAsSession
{
    use ReadsSessionAttributes, RecordsSessionMilestones, RecordsSessionOrigin, RecordsSessionStanding, ScopesActiveSessions;

    /**
     * Return the session's primary key.
     *
     * @return mixed
     */
    public function getSessionIdentifier(): mixed
    {
        return $this->getKey();
    }

    /**
     * Return when the session was last used, or `null` when it never was or the
     * column is not loaded.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->optionalSessionAttribute($this->getLastUsedAtName()));
    }

    /**
     * Column name holding when the session was last used.
     *
     * @return string
     */
    public function getLastUsedAtName(): string
    {
        return 'last_used_at';
    }

    /**
     * Column name holding the IP address the session was last used from.
     *
     * @return string
     */
    public function getLastUsedIpName(): string
    {
        return 'last_used_ip';
    }

    /**
     * Column name holding the user agent the session was last used with.
     *
     * @return string
     */
    public function getLastUsedUserAgentName(): string
    {
        return 'last_used_user_agent';
    }

    /**
     * Return the digest of the current refresh rotation id, or `null` when the
     * session holds no refresh credential.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getRefreshKey(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute($this->getRefreshKeyName(), 'getRefreshKeyName'));
    }

    /**
     * Column name holding the digest of the current refresh rotation id.
     *
     * @return string
     */
    public function getRefreshKeyName(): string
    {
        return 'refresh_key';
    }

    /**
     * Return the digest of the previous refresh rotation id, or `null`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPreviousRefreshKey(): ?string
    {
        return $this->toSessionString($this->loadedSessionAttribute($this->getPreviousRefreshKeyName(), 'getPreviousRefreshKeyName'));
    }

    /**
     * Column name holding the digest of the previous refresh rotation id.
     *
     * @return string
     */
    public function getPreviousRefreshKeyName(): string
    {
        return 'previous_refresh_key';
    }

    /**
     * Return when the current refresh rotation id replaced the previous one, or
     * `null`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getRefreshRotatedAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->loadedSessionAttribute($this->getRefreshRotatedAtName(), 'getRefreshRotatedAtName'));
    }

    /**
     * Column name holding when the current refresh rotation id replaced the
     * previous one.
     *
     * @return string
     */
    public function getRefreshRotatedAtName(): string
    {
        return 'refresh_rotated_at';
    }

    /**
     * Return the idle deadline, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getIdleExpiresAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->loadedSessionAttribute($this->getIdleExpiresAtName(), 'getIdleExpiresAtName'));
    }

    /**
     * Column name holding the idle deadline.
     *
     * @return string
     */
    public function getIdleExpiresAtName(): string
    {
        return 'idle_expires_at';
    }

    /**
     * Return the absolute deadline, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getAbsoluteExpiresAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->loadedSessionAttribute($this->getAbsoluteExpiresAtName(), 'getAbsoluteExpiresAtName'));
    }

    /**
     * Column name holding the absolute deadline.
     *
     * @return string
     */
    public function getAbsoluteExpiresAtName(): string
    {
        return 'absolute_expires_at';
    }

    /**
     * Return the revocation timestamp, or `null` when the session is not
     * revoked.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getRevokedAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->loadedSessionAttribute($this->getRevokedAtName(), 'getRevokedAtName'));
    }

    /**
     * Column name holding the revocation timestamp.
     *
     * @return string
     */
    public function getRevokedAtName(): string
    {
        return 'revoked_at';
    }

    /**
     * Return why the session was revoked, or `null` when it is not revoked or
     * the column is not loaded.
     *
     * @return ?string
     */
    public function getRevokedReason(): ?string
    {
        return $this->toSessionString($this->optionalSessionAttribute($this->getRevokedReasonName()));
    }

    /**
     * Column name holding the revocation reason.
     *
     * @return string
     */
    public function getRevokedReasonName(): string
    {
        return 'revoked_reason';
    }

    /**
     * Hide the digests and the attempt-limit slots from serialisation.
     *
     * @return void
     */
    protected function initializeActsAsSession(): void
    {
        $this->mergeHidden([
            $this->getRefreshKeyName(),
            $this->getPreviousRefreshKeyName(),
            $this->getPendingKeyName(),
            $this->getSupersedesRefreshKeyName(),
            $this->getAttemptWindowsName(),
        ]);
    }
}
