<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;

/**
 * How a request to change an identifier ended: sent, with when the change
 * expires (and, for a change proven by link, the signed link to send to the new
 * identifier); rate limited, with the seconds until another may be requested;
 * or refused because the identity did not authenticate recently enough, or the
 * new identifier is invalid or unchanged.
 *
 * The link is the proof of the change, so it goes only to the new identifier,
 * never back to the client that asked: it is held as a
 * `\SensitiveParameterValue` and read through `link()`, so no dump of the
 * object shows it, and serialising the object throws.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChangeRequest
{
    /** @var ?\SensitiveParameterValue The signed link that confirms the change, for a change proven by link. */
    private ?\SensitiveParameterValue $link;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus  $status
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?int  $retryAfter
     * @param  ?string  $link
     */
    private function __construct(

        /** How the request ended. */
        public IdentifierChangeRequestStatus $status,

        /** When the change stops waiting for its proof, for `sent` only. */
        public ?CarbonImmutable $expiresAt = null,

        /** Seconds until another change may be requested, for `rate_limited` only. */
        public ?int $retryAfter = null,

        // The signed link that confirms the change, for a `sent` change proven
        // by link.
        #[\SensitiveParameter]
        ?string $link = null,
    ) {
        $this->link = $link === null ? null : new \SensitiveParameterValue($link);
    }

    /**
     * The change waits for its proof until the time given: a code was issued
     * and its delivery queued, or the link given was signed.
     *
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  ?string  $link
     * @return self
     */
    public static function sent(CarbonImmutable $expiresAt, #[\SensitiveParameter] ?string $link = null): self
    {
        return new self(IdentifierChangeRequestStatus::SENT, $expiresAt, link: $link);
    }

    /**
     * No change may be requested for the seconds given.
     *
     * @param  int  $retryAfter
     * @return self
     */
    public static function rateLimited(int $retryAfter): self
    {
        return new self(IdentifierChangeRequestStatus::RATE_LIMITED, retryAfter: $retryAfter);
    }

    /**
     * The identity did not authenticate recently enough.
     *
     * @return self
     */
    public static function reauthenticationRequired(): self
    {
        return new self(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED);
    }

    /**
     * The new identifier is not one the type's normaliser accepts.
     *
     * @return self
     */
    public static function identifierInvalid(): self
    {
        return new self(IdentifierChangeRequestStatus::IDENTIFIER_INVALID);
    }

    /**
     * The new identifier is the identity's current one.
     *
     * @return self
     */
    public static function identifierUnchanged(): self
    {
        return new self(IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED);
    }

    /**
     * Whether the change waits for its proof.
     *
     * @return bool
     */
    public function isSent(): bool
    {
        return $this->status === IdentifierChangeRequestStatus::SENT;
    }

    /**
     * The signed link that confirms the change, for a `sent` change proven by
     * link; `null` otherwise. Send it to the new identifier only.
     *
     * @return ?string
     */
    public function link(): ?string
    {
        return $this->link?->getValue();
    }
}
