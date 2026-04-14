<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Stub resolver that returns a constructor-injected principal regardless of the
 * identity or hint supplied.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubFixedPrincipalResolver implements PrincipalResolver
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     */
    public function __construct(

        /** Fixed principal returned by every resolution. */
        private readonly Principal $principal,

    ) {}

    /**
     * Return the fixed principal for any identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): Principal
    {
        unset($identity, $hint);

        return $this->principal;
    }
}
