<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Guard test double whose request resolution binds a configurable identity and
 * counts how often it runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubRequestResolvingGuard extends AbstractGuard
{
    /** @var int Number of times the request was resolved. */
    public int $resolutions = 0;

    /** @var ?\SineMacula\Laravel\Authentication\Contracts\Identity Identity the request's credential resolves to. */
    public ?Identity $resolvable = null;

    /** @var bool Whether resolution calls back into `user()`, as a listener might. */
    public bool $reenter = false;

    /** @var array<int, mixed> What re-entrant `user()` calls returned. */
    public array $reentered = [];

    /**
     * Resolve the configured identity, counting the call, and fall back to the
     * base guard, which resolves nothing, when none is configured.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    protected function resolveUserFromRequest(): ?Identity
    {
        $this->resolutions++;

        if ($this->reenter) {
            $this->reentered[] = $this->user();
        }

        if ($this->resolvable === null) {
            return parent::resolveUserFromRequest();
        }

        $this->setIdentity($this->resolvable);

        return $this->resolvable;
    }
}
