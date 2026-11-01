<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;

/**
 * A session that switched the principal it acts as: the session as it now is,
 * with its new pair, and the principal it recorded before, as the type and
 * identifier it stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SwitchedPrincipal
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh  $session
     * @param  ?string  $previousType
     * @param  ?string  $previousId
     * @param  bool  $switched
     */
    public function __construct(

        /** The session, acting as the target, with its new pair. */
        public ExchangedRefresh $session,

        /** The principal's morph type the session recorded before. */
        public ?string $previousType,

        /** The principal identifier the session recorded before. */
        public ?string $previousId,

        /** Whether this call changed the principal, rather than rotating for the one already recorded or answering a retry. */
        public bool $switched,
    ) {}
}
