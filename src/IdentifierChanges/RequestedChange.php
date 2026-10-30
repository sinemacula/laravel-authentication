<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;

/**
 * A change of identifier being requested, as it is written to the pending
 * changes and signed into a link: the type, the identifier it replaces exactly
 * as stored and whether that one was verified, the new one in its normal form,
 * the request its proofs are bound to, and when it was requested and expires.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RequestedChange
{
    /**
     * Constructor.
     *
     * @param  string  $type
     * @param  ?string  $previous
     * @param  bool  $previousVerified
     * @param  string  $identifier
     * @param  string  $requestId
     * @param  \Carbon\CarbonImmutable  $requestedAt
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** Type of the identifier. */
        public string $type,

        /** The identifier the change replaces, as stored, or `null` for none. */
        #[\SensitiveParameter] public ?string $previous,

        /** Whether the identity had verified the identifier the change replaces when the change was requested. */
        public bool $previousVerified,

        /** The identifier the change sets, in its normal form. */
        #[\SensitiveParameter] public string $identifier,

        /** Random identifier of the request, which its code and link are bound to. */
        public string $requestId,

        /** When the change was requested. */
        public CarbonImmutable $requestedAt,

        /** When the change stops waiting for its proof. */
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * The same change, expiring at the time given when that is earlier: a
     * change proven by code waits no longer than its code works.
     *
     * @param  \Carbon\CarbonImmutable  $deadline
     * @return self
     */
    public function expiringBy(CarbonImmutable $deadline): self
    {
        return $deadline->lessThan($this->expiresAt)
            ? new self($this->type, $this->previous, $this->previousVerified, $this->identifier, $this->requestId, $this->requestedAt, $deadline)
            : $this;
    }
}
