<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Dispatched once for each identity or principal scope a bulk revocation ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignedOutEverywhere implements AuthenticationEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  int  $revoked
     * @param  ?\Carbon\CarbonImmutable  $tokensValidAfter
     */
    public function __construct(

        /** Whose sessions ended, through which guard, and the session kept, if any. */
        public EventContext $context,

        /** Why the sessions were ended. */
        public RevocationReason $reason,

        /** How many sessions this call revoked. */
        public int $revoked,

        /** The cutoff this call set for the scope's access tokens issued without a session, if it set one. */
        public ?CarbonImmutable $tokensValidAfter,
    ) {}

    /**
     * Return whose sessions ended, through which guard, and the session kept.
     *
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    #[\Override]
    public function context(): EventContext
    {
        return $this->context;
    }
}
