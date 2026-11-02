<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * What the removal of one of the factor package's factors did to the identity's
 * sessions: how many it revoked, whether the current session was among them,
 * and, when the current session no longer met what it is asked without that
 * factor, the pending session it returned to and the pending credential it now
 * holds instead of its token pair.
 *
 * The pending credential travels only in a response body, as a sign-in's does.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorRemoval
{
    /**
     * Constructor.
     *
     * @param  int  $revoked
     * @param  bool  $currentRevoked
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     */
    public function __construct(

        /** How many sessions the removal revoked, the current one included when it was revoked. */
        public int $revoked,

        /** Whether the current session was revoked. */
        public bool $currentRevoked = false,

        /** The current session, returned to pending, when it was. */
        public ?PendingSession $pending = null,

        /** The pending credential the current session holds once it returned to pending. */
        public ?Secret $credential = null,
    ) {}

    /**
     * Whether the current session returned to pending.
     *
     * @return bool
     */
    public function isPending(): bool
    {
        return $this->pending !== null;
    }
}
