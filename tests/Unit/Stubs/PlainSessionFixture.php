<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;

/**
 * Plain-object `Session` fixture used by the event serialisation round-trip
 * tests. Intentionally NOT an Eloquent model so the `SerializesModels` trait
 * leaves the instance untouched during serialize.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlainSessionFixture implements Session
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  ?\Carbon\CarbonInterface  $idleExpiresAt
     * @param  ?\Carbon\CarbonInterface  $absoluteExpiresAt
     */
    public function __construct(

        /** Stable identifier used as the `sid` claim. */
        public string $id,

        /** Idle deadline of the session. */
        public ?CarbonInterface $idleExpiresAt = null,

        /** Absolute deadline of the session. */
        public ?CarbonInterface $absoluteExpiresAt = null,
    ) {}

    /**
     * Return the session's stable identifier.
     *
     * @return string
     */
    #[\Override]
    public function getSessionIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Return when the session was last used.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastUsedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return the digest of the current refresh rotation id.
     *
     * @return ?string
     */
    #[\Override]
    public function getRefreshKey(): ?string
    {
        return null;
    }

    /**
     * Return the digest of the previous refresh rotation id.
     *
     * @return ?string
     */
    #[\Override]
    public function getPreviousRefreshKey(): ?string
    {
        return null;
    }

    /**
     * Return when the current refresh rotation id replaced the previous one.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRefreshRotatedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return when the session started; the fixture records none.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getSignedInAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return whether the session is active or pending; it is active.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus
     */
    #[\Override]
    public function getStatus(): SessionStatus
    {
        return SessionStatus::ACTIVE;
    }

    /**
     * Return what the session waits on; nothing.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>
     */
    #[\Override]
    public function getRequires(): array
    {
        return [];
    }

    /**
     * Return the pending credential digest; it holds none.
     *
     * @return ?string
     */
    #[\Override]
    public function getPendingKey(): ?string
    {
        return null;
    }

    /**
     * Return the active tenant id; it acts in none.
     *
     * @return ?string
     */
    #[\Override]
    public function getTenantId(): ?string
    {
        return null;
    }

    /**
     * Return the tenant policy version; none was checked.
     *
     * @return ?string
     */
    #[\Override]
    public function getTenantPolicyVersion(): ?string
    {
        return null;
    }

    /**
     * Return the floor its context changes set; it never changed.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getSwitchedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return the idle deadline.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getIdleExpiresAt(): ?CarbonInterface
    {
        return $this->idleExpiresAt;
    }

    /**
     * Return the absolute deadline.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getAbsoluteExpiresAt(): ?CarbonInterface
    {
        return $this->absoluteExpiresAt;
    }

    /**
     * Return when the session was revoked, or null.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return why the session was revoked, or null.
     *
     * @return ?string
     */
    #[\Override]
    public function getRevokedReason(): ?string
    {
        return null;
    }

    /**
     * Return the guard the session belongs to, or null.
     *
     * @return ?string
     */
    #[\Override]
    public function getGuard(): ?string
    {
        return null;
    }

    /**
     * Return the sign-in method that started the session, or null.
     *
     * @return ?string
     */
    #[\Override]
    public function getSignInMethod(): ?string
    {
        return null;
    }

    /**
     * Return the identifier type the session's sign-in used, or null.
     *
     * @return ?string
     */
    #[\Override]
    public function getSignInIdentifierType(): ?string
    {
        return null;
    }
}
