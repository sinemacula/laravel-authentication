<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * Device contract.
 *
 * Describes the generic read-only device surface carried through token
 * issuance, guard state, and package events. Persistence-capable refresh
 * rotation and last-seen writes require the narrower `EloquentDevice` boundary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Device
{
    /**
     * Return the device's stable identifier (typically a UUID v7).
     *
     * @return mixed
     */
    public function getDeviceIdentifier(): mixed;

    /**
     * Return when the device was last successfully authenticated. Returns
     * `CarbonInterface` so consumer apps that configure `CarbonImmutable` casts
     * are not silently broken.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastLoggedIn(): ?CarbonInterface;

    /**
     * Return when the device's MFA factor was last verified.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastMfaVerification(): ?CarbonInterface;

    /**
     * Return the operating system string captured at registration.
     *
     * @return string
     */
    public function getOperatingSystem(): string;

    /**
     * Return the hashed refresh-key digest stored on the device row. NEVER the
     * plaintext rotation identifier - the refresh exchange verifies the
     * plaintext against this digest via `hash_equals()`. Returns `null` when no
     * refresh credential has been issued or after revocation cleared the
     * column. The refresh exchange reads it inside `WriteConnection::during()`
     * for the device, as it does `getRevokedAt()`.
     *
     * @return ?string
     */
    public function getRefreshKey(): ?string;

    /**
     * Return when the device was revoked, or `null`. A non-null value rejects
     * the device everywhere: the bearer path treats it exactly like a missing
     * device, so access tokens naming it stop authenticating at once, and the
     * refresh exchange rejects it with reason `device_revoked`.
     *
     * It runs inside `WriteConnection::during()` for the device, together with
     * the lookup that found it on the bearer path: model reads on any
     * connection, and query-builder reads on the device's own connection, go to
     * the write connection, so a revocation derived from a relation or another
     * table cannot come from a lagging replica.
     *
     * A revocation that was not loaded must not read as `null`: `ActsAsDevice`
     * throws a `LogicException` for a device loaded without its column.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getRevokedAt(): ?CarbonInterface;
}
