<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;

/**
 * Session contract.
 *
 * Describes the generic read-only session surface carried through token
 * issuance, guard state, and package events. Persistence-capable refresh
 * rotation and last-use writes require the narrower `EloquentSession` boundary.
 *
 * A session is one sign-in, on one application, on one device: it holds the
 * refresh credential, the idle and absolute deadlines that end it, and its
 * revocation. It is active, or pending while it waits on requirements (a
 * further factor, a choice of principal), when it holds a pending credential
 * and no refresh credential the package accepts.
 *
 * Every refresh and revocation state accessor is read inside
 * `WriteConnection::during()` for the session by the package: model reads on
 * any connection, and query-builder reads on the session's own connection, go
 * to the write connection, so state derived from a relation or another table
 * cannot come from a lagging replica. A state value that was not loaded must
 * not read as `null`: `ActsAsSession` throws a `LogicException` for a session
 * loaded without the column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Session
{
    /**
     * Return the session's identifier, which is always its primary key: tokens
     * carry it in `sid` and every lookup finds the session by primary key.
     *
     * @return mixed
     */
    public function getSessionIdentifier(): mixed;

    /**
     * Return when the session was last used to authenticate, or `null`. Returns
     * `CarbonInterface` so applications that configure `CarbonImmutable` casts
     * are not silently broken.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface;

    /**
     * Return the digest of the session's current refresh rotation id. NEVER the
     * plaintext rotation id: the refresh exchange compares the presented
     * plaintext against this digest with `hash_equals()`. Returns `null` when
     * the session holds no refresh credential (none issued, or cleared by
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
     * Return when the session started: the sign-in that created the session.
     * The absolute deadline is counted from it. `null` when none was recorded.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getSignedInAt(): ?CarbonInterface;

    /**
     * Return the floor for the issue time of the session's access tokens, moved
     * by every change of its context (its principal or active tenant, a return
     * to pending, an activation after one), or `null` when it never changed.
     * Access tokens naming the session that were issued before it are rejected.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getSwitchedAt(): ?CarbonInterface;

    /**
     * Return whether the session is active or pending. A stored value that is
     * neither, or a status that was not loaded, throws a `LogicException`
     * rather than reading as either.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus
     *
     * @throws \LogicException
     */
    public function getStatus(): SessionStatus;

    /**
     * Return what a pending session waits on, in the order it must be met: a
     * list of `PendingRequirement`s, empty for an active session. A stored
     * value that is not such a list throws a `LogicException`.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>
     *
     * @throws \LogicException
     */
    public function getRequires(): array;

    /**
     * Return the digest of a pending session's credential secret, or `null` for
     * an active session. NEVER the plaintext: the package compares the
     * presented secret against it with `hash_equals()`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getPendingKey(): ?string;

    /**
     * Return the opaque id of the session's active tenant, or `null` when it
     * acts in none.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getTenantId(): ?string;

    /**
     * Return the version of the tenant authentication policy the session was
     * last checked against, or `null` when the policy answered none.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getTenantPolicyVersion(): ?string;

    /**
     * Return the idle deadline: the session ends at this time unless a refresh
     * extends it. `null` means the session has no deadline and fails closed
     * everywhere.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getIdleExpiresAt(): ?CarbonInterface;

    /**
     * Return the absolute deadline: the session ends at this time however often
     * it is refreshed. `null` means the session has no absolute deadline (the
     * application sets no absolute limit and the sign-in supplied no deadline
     * of its own), so it ends only when it goes idle. A session loaded without
     * the column throws a `LogicException` rather than reading as `null`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getAbsoluteExpiresAt(): ?CarbonInterface;

    /**
     * Return when the session was revoked, or `null`. A non-null value rejects
     * the session everywhere: the bearer path treats it exactly like a missing
     * session, so access tokens naming it stop authenticating at once, and the
     * refresh exchange rejects it with reason `session_revoked`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getRevokedAt(): ?CarbonInterface;

    /**
     * Return why the session was revoked, or `null`.
     *
     * @return ?string
     */
    public function getRevokedReason(): ?string;

    /**
     * Return the name of the guard the session belongs to, or `null` when none
     * was recorded. A session of another guard is never accepted by this
     * guard's sign-in, refresh or bearer paths.
     *
     * @return ?string
     */
    public function getGuard(): ?string;

    /**
     * Return the name of the sign-in method that started the session, or `null`
     * when none was recorded.
     *
     * @return ?string
     */
    public function getSignInMethod(): ?string;

    /**
     * Return the type of identifier the sign-in that started the session used,
     * such as `email`, or `null` when it used none or none was recorded. A
     * switch of principal admits its target with it, as that sign-in admitted
     * its principal, so a value that cannot be read throws rather than reading
     * as `null`.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getSignInIdentifierType(): ?string;
}
