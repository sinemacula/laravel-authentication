<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * How a request to change an identifier ended.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierChangeRequest
{
    /** @var ?\SineMacula\Laravel\Authentication\Secrets\Secret The signed link that confirms the change, for a change proven by link. */
    private ?Secret $link;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus  $status
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?int  $retryAfter
     * @param  ?string  $link
     * @param  ?string  $challengeId
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** How the request ended. */
        public IdentifierChangeRequestStatus $status,

        /** When the change stops waiting for its proof, for `sent` only. */
        public ?CarbonImmutable $expiresAt = null,

        /** Seconds until another change may be requested, for `rate_limited` only. */
        public ?int $retryAfter = null,

        // The signed link that confirms a `sent` change proven by link.
        #[\SensitiveParameter]
        ?string $link = null,

        /** The challenge the code was sent for, which `confirmByCode()` names, for a `sent` change proven by code. */
        public ?string $challengeId = null,
    ) {
        $this->link = $link === null ? null : new Secret($link);
    }

    /**
     * The change waits for its proof until the time given.
     *
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  ?string  $link
     * @param  ?string  $challengeId
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function sent(CarbonImmutable $expiresAt, #[\SensitiveParameter] ?string $link = null, ?string $challengeId = null): self
    {
        return new self(IdentifierChangeRequestStatus::SENT, $expiresAt, link: $link, challengeId: $challengeId);
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
     * The signed link that confirms a `sent` change proven by link.
     *
     * @return ?\SineMacula\Laravel\Authentication\Secrets\Secret
     */
    public function link(): ?Secret
    {
        return $this->link;
    }
}
