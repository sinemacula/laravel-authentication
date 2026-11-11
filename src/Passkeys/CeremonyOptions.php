<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;

/**
 * What a client is handed to run a passkey ceremony: the challenge id, the
 * browser options in WebAuthn JSON form and the challenge's expiry.
 *
 * @api
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CeremonyOptions implements \JsonSerializable, Arrayable
{
    /**
     * Constructor.
     *
     * @param  string  $challengeId
     * @param  array<string, mixed>  $options
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** Id of the challenge, which the client sends back with its response. */
        public string $challengeId,

        /** The options to pass to the browser, in their WebAuthn JSON form. */
        public array $options,

        /** When the challenge expires and can no longer be answered. */
        public CarbonImmutable $expiresAt,
    ) {}

    /**
     * The challenge id, the options and the expiry (ISO-8601).
     *
     * @return array{challenge: string, options: array<string, mixed>, expires_at: string}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'challenge'  => $this->challengeId,
            'options'    => $this->options,
            'expires_at' => $this->expiresAt->toIso8601String(),
        ];
    }

    /**
     * The options as JSON serialises them: the same as `toArray()`.
     *
     * @return array{challenge: string, options: array<string, mixed>, expires_at: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
