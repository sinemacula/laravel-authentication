<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;

/**
 * A change of identifier waiting for its proof, as `pending()` reports it: the
 * type, the new identifier in its normal form, and when the change was
 * requested and expires. The identity keeps its current identifier until the
 * change is confirmed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PendingIdentifierChange
{
    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @param  \Carbon\CarbonImmutable  $requestedAt
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** Type of the identifier, for example `email`. */
        public string $type,

        /** The identifier the change would set, in its normal form. */
        public string $identifier,

        /** When the change was requested. */
        public CarbonImmutable $requestedAt,

        /** When the change stops waiting for its proof. */
        public CarbonImmutable $expiresAt,
    ) {}
}
