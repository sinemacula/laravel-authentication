<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;

/**
 * Eloquent `Session` fixture that intentionally does NOT satisfy the explicit
 * `EloquentSession` persistence boundary. Used by configuration validation
 * tests to prove refresh and last-use flows fail fast for unsupported Eloquent
 * session implementations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 *
 * @internal
 */
final class StubBareSession extends Model implements Session
{
    /** @var bool Indicates whether the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string|null The table associated with the model. */
    protected $table = 'bare_sessions';

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> Mass-assignment guard list. */
    protected $guarded = [];

    /**
     * Bare session id accessor.
     *
     * @return mixed
     */
    #[\Override]
    public function getSessionIdentifier(): mixed
    {
        return $this->getAttribute('id');
    }

    /**
     * Inert last-use accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastUsedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert current refresh digest accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getRefreshKey(): ?string
    {
        return null;
    }

    /**
     * Inert previous refresh digest accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getPreviousRefreshKey(): ?string
    {
        return null;
    }

    /**
     * Inert rotation time accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRefreshRotatedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert session start accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getSignedInAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert status accessor: active.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus
     */
    #[\Override]
    public function getStatus(): SessionStatus
    {
        return SessionStatus::ACTIVE;
    }

    /**
     * Inert requirements accessor: none.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>
     */
    #[\Override]
    public function getRequires(): array
    {
        return [];
    }

    /**
     * Inert pending credential digest accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getPendingKey(): ?string
    {
        return null;
    }

    /**
     * Inert active tenant accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getTenantId(): ?string
    {
        return null;
    }

    /**
     * Inert tenant policy version accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getTenantPolicyVersion(): ?string
    {
        return null;
    }

    /**
     * Inert context-change floor accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getSwitchedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert idle deadline accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getIdleExpiresAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert absolute deadline accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getAbsoluteExpiresAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert revocation time accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert revocation reason accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getRevokedReason(): ?string
    {
        return null;
    }

    /**
     * Inert guard accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getGuard(): ?string
    {
        return null;
    }

    /**
     * Inert sign-in method accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getSignInMethod(): ?string
    {
        return null;
    }

    /**
     * Inert sign-in identifier type accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getSignInIdentifierType(): ?string
    {
        return null;
    }
}
