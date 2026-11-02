<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

/**
 * An active session that returned to pending: the pending session it now is,
 * and the pending credential it now holds instead of its token pair.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ReturnedToPending
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  string  $credential
     */
    public function __construct(

        /** The session, now pending. */
        public PendingSession $pending,

        /** The pending credential it now holds. */
        #[\SensitiveParameter]
        public string $credential,
    ) {}
}
