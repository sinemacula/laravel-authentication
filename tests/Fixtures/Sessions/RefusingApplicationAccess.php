<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Application access an application binds to keep some principals out of a
 * guard: the principals the rule names may not use it, and every other may.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefusingApplicationAccess implements ApplicationAccess
{
    /**
     * Constructor.
     *
     * @param  \Closure(string, \SineMacula\Laravel\Authentication\Contracts\Principal): bool  $refuses
     */
    public function __construct(

        /** Whether the guard refuses the principal. */
        private \Closure $refuses,
    ) {}

    /**
     * Let the principal use the application unless the rule refuses it.
     *
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    #[\Override]
    public function mayUse(string $application, Principal $principal): bool
    {
        return !($this->refuses)($application, $principal);
    }
}
