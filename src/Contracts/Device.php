<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * Device contract.
 *
 * Describes the generic read-only device surface carried through token
 * issuance, guard state, and package events. Persistence-capable refresh
 * rotation and last-use writes require the narrower `EloquentDevice` boundary.
 *
 * A device is one signed-in session: it holds the refresh credential, the idle
 * and absolute deadlines that end the session, and its revocation.
 *
 * Every refresh and revocation state accessor is read inside
 * `WriteConnection::during()` for the device by the package: model reads on any
 * connection, and query-builder reads on the device's own connection, go to the
 * write connection, so state derived from a relation or another table cannot
 * come from a lagging replica. A state value that was not loaded must not read
 * as `null`: `ActsAsDevice` throws a `LogicException` for a device loaded
 * without the column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Device
{
    /**
     * Return the device's identifier, which is always its primary key: tokens
     * carry it in `did` and every lookup finds the device by primary key.
     *
     * @return mixed
     */
    public function getDeviceIdentifier(): mixed;

    /**
     * Return when the device was last used to authenticate, or `null`. Returns
     * `CarbonInterface` so applications that configure `CarbonImmutable` casts
     * are not silently broken.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface;

    /**
     * Return the digest of the device's current refresh rotation id. NEVER the
     * plaintext rotation id: the refresh exchange compares the presented
     * plaintext against this digest with `hash_equals()`. Returns `null` when
     * the device holds no refresh credential (none issued, or cleared by
     * revocation).
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getRefreshKey(): ?string;

    /**
     * Return the digest of the rotation id the current one replaced, or `null`
     * before the first rotation and after revocation.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPreviousRefreshKey(): ?string;

    /**
     * Return when the current rotation id replaced the previous one, or `null`
     * before the first rotation.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getRefreshRotatedAt(): ?CarbonInterface;

    /**
     * Return when the device's session started: the sign-in that created the
     * device, or the last one that continued it on the same client. The
     * absolute deadline is counted from it. `null` only for a device with no
     * session.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getSignedInAt(): ?CarbonInterface;

    /**
     * Return when the session last switched the principal it acts as, or `null`
     * when it never did. Access tokens naming the device that were issued
     * before it are rejected.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getPrincipalSwitchedAt(): ?CarbonInterface;

    /**
     * Return the idle deadline: the session ends at this time unless a refresh
     * extends it. `null` means the device has no session and fails closed
     * everywhere.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getIdleExpiresAt(): ?CarbonInterface;

    /**
     * Return the absolute deadline: the session ends at this time however often
     * it is refreshed. `null` means the device has no session and fails closed
     * everywhere.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getAbsoluteExpiresAt(): ?CarbonInterface;

    /**
     * Return when the device was revoked, or `null`. A non-null value rejects
     * the device everywhere: the bearer path treats it exactly like a missing
     * device, so access tokens naming it stop authenticating at once, and the
     * refresh exchange rejects it with reason `device_revoked`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getRevokedAt(): ?CarbonInterface;

    /**
     * Return why the device was revoked, or `null`.
     *
     * @return ?string
     */
    public function getRevokedReason(): ?string;

    /**
     * Return the name of the guard whose session the device holds, or `null`
     * when none was recorded. A device of another guard is never accepted by
     * this guard's sign-in, refresh or bearer paths.
     *
     * @return ?string
     */
    public function getGuard(): ?string;

    /**
     * Return the name of the sign-in method that started the device's session
     * (or last restarted it on the same client), or `null` when none was
     * recorded.
     *
     * @return ?string
     */
    public function getSignInMethod(): ?string;

    /**
     * Return the type of identifier the sign-in that started the device's
     * session (or last restarted it on the same client) used, such as `email`,
     * or `null` when it used none or none was recorded. A switch of principal
     * admits its target with it, as that sign-in admitted its principal.
     *
     * @return ?string
     */
    public function getSignInIdentifierType(): ?string;
}
