<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\Carbon;

/**
 * Device contract.
 *
 * Describes a refreshable device record bound to an authenticated
 * identity. Implementations are typically Eloquent models.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
interface Device
{
    /** Return the device's stable identifier (typically the ULID primary key). */
    public function getDeviceIdentifier(): mixed;

    /** Return when the device was last successfully authenticated. */
    public function getLastLoggedIn(): ?Carbon;

    /** Return when the device's MFA factor was last verified. */
    public function getLastMfaVerification(): ?Carbon;

    /** Return the operating system string captured at registration. */
    public function getOperatingSystem(): string;

    /** Return the (hashed) refresh key used for refresh-credential lookup. */
    public function getRefreshKey(): string;
}
