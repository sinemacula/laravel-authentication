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
final class PlainDeviceFixture implements Device
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $os
     */
    public function __construct(

        /** Stable identifier used as the `did` claim. */
        public readonly string $id,

        /** Operating-system string embedded in the device row. */
        public readonly string $os = 'plain-os',

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
     * Return when the device was last successfully authenticated.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastLoggedIn(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return when the device's MFA factor was last verified.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastMfaVerification(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Return the operating system string captured at registration.
     *
     * @return string
     */
    #[\Override]
    public function getOperatingSystem(): string
    {
        return $this->os;
    }

    /**
     * Return the hashed refresh-key digest stored on the device row.
     *
     * @return ?string
     */
    #[\Override]
    public function getRefreshKey(): ?string
    {
        return null;
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
}
