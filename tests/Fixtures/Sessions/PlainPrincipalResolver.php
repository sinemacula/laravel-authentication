<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * A principal resolver that answers the principal it was given, whatever it is
 * asked, and records the hints it is asked with: a stand-in for an
 * application's resolver of principals that are not Eloquent models.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainPrincipalResolver implements PrincipalResolver
{
    /** @var list<mixed> The hints it was asked with, in order. */
    public array $hints = [];

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     */
    public function __construct(

        /** The principal it answers with. */
        private readonly ?Principal $principal,
    ) {}

    /**
     * Record the hint, and answer the principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    #[\Override]
    public function resolve(Identity $identity, mixed $hint = null): ?Principal
    {
        $this->hints[] = $hint;

        return $this->principal;
    }
}
