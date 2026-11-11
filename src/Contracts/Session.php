<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Carbon\CarbonInterface;

/**
 * The read-only surface of one sign-in, on one application, on one device.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface Session extends SessionStanding
{
    /**
     * Return the session's primary key, which tokens carry in `sid`.
     *
     * @return mixed
     */
    public function getSessionIdentifier(): mixed;

    /**
     * Return when the session was last used to authenticate, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     */
    public function getLastUsedAt(): ?CarbonInterface;

    /**
     * Return the digest, never the plaintext, of the current refresh rotation
     * id, or `null` when the session holds no refresh credential.
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
     * Return when the sign-in that created the session happened, or `null` when
     * none was recorded.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getSignedInAt(): ?CarbonInterface;

    /**
     * Return the time before which the session's access tokens are rejected, or
     * `null` when its context never changed.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getSwitchedAt(): ?CarbonInterface;

    /**
     * Return the idle deadline a refresh extends; `null` fails closed
     * everywhere.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getIdleExpiresAt(): ?CarbonInterface;

    /**
     * Return the deadline no refresh extends, or `null` when the session ends
     * only when it goes idle.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getAbsoluteExpiresAt(): ?CarbonInterface;

    /**
     * Return when the session was revoked, or `null`.
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
     * was recorded.
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
     * such as `email`, or `null` when it used none or none was recorded.
     *
     * @return ?string
     *
     * @throws \LogicException
     */
    public function getSignInIdentifierType(): ?string;
}
