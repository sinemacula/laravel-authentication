<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched once an API key's rotation is committed; the context describes the
 * new key.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApiKeyRotated extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $previousKeyId
     */
    public function __construct(

        // The new key and whose it is.
        EventContext $context,

        /** Identifier of the key the new one replaces. */
        public string $previousKeyId,
    ) {
        parent::__construct($context);
    }
}
