<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Illuminate\Queue\SerializesModels;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Dispatched when a principal is bound to a guard during authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class PrincipalAssigned
{
    use SerializesModels;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     */
    public function __construct(

        /** Name of the guard that bound the principal. */
        public string $guard,

        /** Principal that was bound to the guard. */
        public Principal $principal,

    ) {}
}
