<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Support\Arrayable;
use SineMacula\Laravel\Authentication\Models\Passkey;

/**
 * What a passkey list shows of one passkey: its id (to remove it by), the name
 * it was registered with, the transports it reported, its authenticator's
 * AAGUID, whether it may be and is backed up (a synced passkey), and when it
 * was registered and last used.
 *
 * Safe to return to the identity it belongs to as it is: it never holds the
 * credential id, the public key, the user handle or the sign counter.
 * `toArray()` and JSON use snake_case keys and ISO-8601 times.
 *
 * @api
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeySummary implements \JsonSerializable, Arrayable
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  ?string  $name
     * @param  list<string>  $transports
     * @param  ?string  $aaguid
     * @param  bool  $backupEligible
     * @param  bool  $backedUp
     * @param  \Carbon\CarbonImmutable  $createdAt
     * @param  ?\Carbon\CarbonImmutable  $lastUsedAt
     */
    public function __construct(

        /** The passkey's id, as its events carry it and `remove()` takes it. */
        public string $id,

        /** The name the passkey was registered with. */
        public ?string $name,

        /** The transports the authenticator reported. */
        public array $transports,

        /** The authenticator's AAGUID, or `null` when it reported none. */
        public ?string $aaguid,

        /** Whether the passkey may be backed up (synced). */
        public bool $backupEligible,

        /** Whether the passkey was backed up when last used. */
        public bool $backedUp,

        /** When the passkey was registered. */
        public CarbonImmutable $createdAt,

        /** When the passkey was last used, or `null` when it never was. */
        public ?CarbonImmutable $lastUsedAt,
    ) {}

    /**
     * Summarise a stored passkey.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Passkey  $passkey
     * @return self
     */
    public static function of(Passkey $passkey): self
    {
        return new self(
            $passkey->id,
            $passkey->name,
            $passkey->transports,
            $passkey->aaguid,
            $passkey->backup_eligible,
            $passkey->backup_state,
            $passkey->created_at->toImmutable(),
            $passkey->last_used_at?->toImmutable(),
        );
    }

    /**
     * The summary with snake_case keys and ISO-8601 times.
     *
     * @return array{id: string, name: ?string, transports: list<string>, aaguid: ?string, backup_eligible: bool, backed_up: bool, created_at: string, last_used_at: ?string}
     */
    #[\Override]
    public function toArray(): array
    {
        return [
            'id'              => $this->id,
            'name'            => $this->name,
            'transports'      => $this->transports,
            'aaguid'          => $this->aaguid,
            'backup_eligible' => $this->backupEligible,
            'backed_up'       => $this->backedUp,
            'created_at'      => $this->createdAt->toIso8601String(),
            'last_used_at'    => $this->lastUsedAt?->toIso8601String(),
        ];
    }

    /**
     * The summary as JSON serialises it: the same as `toArray()`.
     *
     * @return array{id: string, name: ?string, transports: list<string>, aaguid: ?string, backup_eligible: bool, backed_up: bool, created_at: string, last_used_at: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
