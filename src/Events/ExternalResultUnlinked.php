<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a result an external identity provider verified links to no
 * identity.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExternalResultUnlinked extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $issuer
     */
    public function __construct(

        // The application the result was handed to, the client, and the
        // connection the result came through.
        EventContext $context,

        /** The issuer the provider asserted. */
        public string $issuer,
    ) {
        parent::__construct($context);
    }
}
