<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Database\Eloquent\Relations\MorphTo;

/**
 * Explicit persistence boundary for refreshable Eloquent-backed sessions.
 *
 * Extends the generic `Session` read surface with the relations and the
 * column-name accessors behind each persisted session attribute, which the
 * package's session creation, refresh rotation, revocation, and last-use
 * persistence paths rely on. The columns that record what the session started
 * with are named through `EloquentSessionOrigin`, and those that record where
 * it stands (pending or active, and its active tenant) through
 * `EloquentSessionStanding`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface EloquentSession extends EloquentSessionOrigin, EloquentSessionStanding, Session
{
    /**
     * Polymorphic relation to the owning authenticatable identity.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function authenticatable(): MorphTo;

    /**
     * Polymorphic relation to the principal the session acts as.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    public function principal(): MorphTo;

    /**
     * Column name holding when the session was last used.
     *
     * @return string
     */
    public function getLastUsedAtName(): string;

    /**
     * Column name holding the IP address the session was last used from.
     *
     * @return string
     */
    public function getLastUsedIpName(): string;

    /**
     * Column name holding the user agent the session was last used with.
     *
     * @return string
     */
    public function getLastUsedUserAgentName(): string;

    /**
     * Column name holding the digest of the current refresh rotation id.
     *
     * @return string
     */
    public function getRefreshKeyName(): string;

    /**
     * Column name holding the digest of the previous refresh rotation id.
     *
     * @return string
     */
    public function getPreviousRefreshKeyName(): string;

    /**
     * Column name holding when the current refresh rotation id replaced the
     * previous one.
     *
     * @return string
     */
    public function getRefreshRotatedAtName(): string;

    /**
     * Column name holding the session's generation: a random identifier the
     * session service writes when it inserts the session and nothing changes,
     * which tells the session apart from any other a model that reissues keys
     * later puts under its key.
     *
     * @return string
     */
    public function getGenerationName(): string;

    /**
     * Column name holding when the session started.
     *
     * @return string
     */
    public function getSignedInAtName(): string;

    /**
     * Column name holding the floor for the issue time of the session's access
     * tokens.
     *
     * @return string
     */
    public function getSwitchedAtName(): string;

    /**
     * Column name holding the idle deadline.
     *
     * @return string
     */
    public function getIdleExpiresAtName(): string;

    /**
     * Column name holding the absolute deadline.
     *
     * @return string
     */
    public function getAbsoluteExpiresAtName(): string;

    /**
     * Column name holding the revocation timestamp.
     *
     * @return string
     */
    public function getRevokedAtName(): string;

    /**
     * Column name holding the revocation reason.
     *
     * @return string
     */
    public function getRevokedReasonName(): string;
}
