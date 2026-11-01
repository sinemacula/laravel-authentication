<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonInterface;

/**
 * Default Eloquent-backed accessors for the generation a session started with,
 * when it started and when it last switched the principal it acts as, using
 * conventional attribute names. Override the `*Name()` methods to remap
 * columns.
 *
 * The times are session state: a session loaded without either column throws a
 * `LogicException` rather than reading the missing value as `null`. The
 * generation is compared as loaded, so a session loaded without it is never
 * taken for the session stored under its key.
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
     * Return when the session last switched its principal, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getPrincipalSwitchedAt(): ?CarbonInterface
    {
        return $this->toSessionTimestamp($this->loadedSessionAttribute($this->getPrincipalSwitchedAtName(), 'getPrincipalSwitchedAtName'));
    }

    /**
     * Column name holding when the session last switched its principal.
     *
     * @return string
     */
    public function getPrincipalSwitchedAtName(): string
    {
        return 'principal_switched_at';
    }
}
