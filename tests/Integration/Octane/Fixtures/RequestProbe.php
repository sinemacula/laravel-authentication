<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

/**
 * A scoped service holding the `X-Request-Id` of the request it was resolved
 * for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestProbe
{
    /**
     * Constructor.
     *
     * @param  ?string  $requestId
     */
    public function __construct(

        /** The `X-Request-Id` of the request the probe was resolved for. */
        public ?string $requestId,
    ) {}
}
