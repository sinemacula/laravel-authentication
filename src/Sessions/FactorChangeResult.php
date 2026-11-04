<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus;

/**
 * What judging the current session again after a change of the factor package's
 * did to it: kept active, returned to pending, with the pending session and the
 * pending credential it now holds instead of its token pair, revoked, or
 * skipped, when this call did none of those.
 *
 * The status names every outcome; `pending` and `credential` are set only for
 * `pending`. The pending credential travels only in a response body, as a
 * sign-in's does, and matches the session only once the transaction the change
 * was made in commits: if that rolls back, the session stays active and the
 * credential matches nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FactorChangeResult
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus  $status
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     */
    private function __construct(

        /** What the judgement did to the current session. */
        public FactorChangeStatus $status,

        /** The current session, returned to pending, for `pending` only. */
        public ?PendingSession $pending = null,

        /** The pending credential the current session now holds, for `pending` only. */
        public ?Secret $credential = null,
    ) {}

    /**
     * The current session still meets what it is asked and stays active.
     *
     * @return self
     */
    public static function active(): self
    {
        return new self(FactorChangeStatus::ACTIVE);
    }

    /**
     * The current session returned to pending, holding the pending credential
     * given.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @return self
     */
    public static function pending(PendingSession $pending, Secret $credential): self
    {
        return new self(FactorChangeStatus::PENDING, $pending, $credential);
    }

    /**
     * The current session was revoked by this call.
     *
     * @return self
     */
    public static function revoked(): self
    {
        return new self(FactorChangeStatus::REVOKED);
    }

    /**
     * This call neither kept, returned nor revoked the current session.
     *
     * @return self
     */
    public static function skipped(): self
    {
        return new self(FactorChangeStatus::SKIPPED);
    }

    /**
     * Whether the current session stays active.
     *
     * @return bool
     */
    public function isActive(): bool
    {
        return $this->status === FactorChangeStatus::ACTIVE;
    }

    /**
     * Whether the current session returned to pending.
     *
     * @return bool
     */
    public function isPending(): bool
    {
        return $this->status === FactorChangeStatus::PENDING;
    }

    /**
     * Whether the current session was revoked by this call.
     *
     * @return bool
     */
    public function isRevoked(): bool
    {
        return $this->status === FactorChangeStatus::REVOKED;
    }

    /**
     * Whether this call neither kept, returned nor revoked the current session.
     *
     * @return bool
     */
    public function isSkipped(): bool
    {
        return $this->status === FactorChangeStatus::SKIPPED;
    }
}
