<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Device;

/**
 * Plain-object `Device` fixture used by the event serialisation round-trip
 * tests. Intentionally NOT an Eloquent model so the `SerializesModels` trait
 * leaves the instance untouched during serialize.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlainDeviceFixture implements Device
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  ?\Carbon\CarbonInterface  $idleExpiresAt
     * @param  ?\Carbon\CarbonInterface  $absoluteExpiresAt
     */
    public function __construct(

        /** Stable identifier used as the `did` claim. */
        public string $id,

        /** Idle deadline of the device's session. */
        public ?CarbonInterface $idleExpiresAt = null,

        /** Absolute deadline of the device's session. */
        public ?CarbonInterface $absoluteExpiresAt = null,
    ) {}

    /**
     * Return the device's stable identifier.
     *
     * @return string
     */
    #[\Override]
    public function getDeviceIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Return when the device was last used.
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
     * Return when the device was revoked, or null.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return why the device was revoked, or null.
     *
     * @return ?string
     */
    #[\Override]
    public function getRevokedReason(): ?string
    {
        return null;
    }

    /**
     * Return the guard whose session the device holds, or null.
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
}
