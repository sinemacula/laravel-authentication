<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonInterface;

/**
 * Default Eloquent-backed accessors for a session's generation, start, context
 * change floor and issuance sequence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait RecordsSessionMilestones
{
    /**
     * Column name holding the session's generation.
     *
     * @return string
     */
    public function getGenerationName(): string
    {
        return 'generation';
    }

    /**
     * Return when the session started, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getSignedInAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->loadedSessionAttribute($this->getSignedInAtName(), 'getSignedInAtName'));
    }

    /**
     * Column name holding when the session started.
     *
     * @return string
     */
    public function getSignedInAtName(): string
    {
        return 'signed_in_at';
    }

    /**
     * Return the floor for the issue time of the session's access tokens, or
     * `null` when its context never changed.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getSwitchedAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->loadedSessionAttribute($this->getSwitchedAtName(), 'getSwitchedAtName'));
    }

    /**
     * Column name holding the floor for the issue time of the session's access
     * tokens.
     *
     * @return string
     */
    public function getSwitchedAtName(): string
    {
        return 'switched_at';
    }

    /**
     * Column name holding the session's issuance sequence, the issuance guard.
     *
     * @return string
     */
    public function getIssuanceSequenceName(): string
    {
        return 'issuance_sequence';
    }
}
