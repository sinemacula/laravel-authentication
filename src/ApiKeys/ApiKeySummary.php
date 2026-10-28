<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Models\ApiKey;

/**
 * What an application may show about an API key: its id, its public part, the
 * guard it authenticates for, its name and scopes, and when it expires, was
 * last used, rotated (and by which key) or revoked. Never its secret or the
 * secret's digest.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApiKeySummary
{
    /**
     * Constructor.
     *
     * @param  string  $id
     * @param  string  $prefix
     * @param  string  $guard
     * @param  ?string  $name
     * @param  list<string>  $scopes
     * @param  ?\Carbon\CarbonImmutable  $expiresAt
     * @param  ?\Carbon\CarbonImmutable  $lastUsedAt
     * @param  ?\Carbon\CarbonImmutable  $rotatedAt
     * @param  ?string  $replacedBy
     * @param  ?\Carbon\CarbonImmutable  $revokedAt
     * @param  ?\Carbon\CarbonImmutable  $createdAt
     */
    public function __construct(

        /** The key's id, which names it to the service and in events. */
        public string $id,

        /** The key's public part, `<prefix>_<public>`, which is also its OAuth client id. */
        public string $prefix,

        /** The guard the key authenticates for. */
        public string $guard,

        /** The name given at issue, if any. */
        public ?string $name,

        /** The scopes the key grants. */
        public array $scopes,

        /** When the key stops authenticating, if ever. */
        public ?CarbonImmutable $expiresAt,

        /** When the key's last use was recorded, if ever. */
        public ?CarbonImmutable $lastUsedAt,

        /** When the key was rotated, if it was. */
        public ?CarbonImmutable $rotatedAt,

        /** The id of the key that replaced it, if it was rotated. */
        public ?string $replacedBy,

        /** When the key was revoked, if it was. */
        public ?CarbonImmutable $revokedAt,

        /** When the key was issued. */
        public ?CarbonImmutable $createdAt,
    ) {}

    /**
     * Summarise a key.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @return self
     */
    public static function of(ApiKey $key): self
    {
        return new self(
            $key->id,
            $key->prefix,
            $key->guard,
            $key->name,
            $key->scopes,
            self::immutable($key->expires_at),
            self::immutable($key->last_used_at),
            self::immutable($key->rotated_at),
            $key->replaced_by,
            self::immutable($key->revoked_at),
            self::immutable($key->created_at),
        );
    }

    /**
     * The summary as an array of plain values, times in ISO-8601.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{id: string, prefix: string, guard: string, name: ?string, scopes: list<string>, expires_at: ?string, last_used_at: ?string, rotated_at: ?string, replaced_by: ?string, revoked_at: ?string, created_at: ?string}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public function toArray(): array
    {
        return [
            'id'           => $this->id,
            'prefix'       => $this->prefix,
            'guard'        => $this->guard,
            'name'         => $this->name,
            'scopes'       => $this->scopes,
            'expires_at'   => $this->expiresAt?->toIso8601String(),
            'last_used_at' => $this->lastUsedAt?->toIso8601String(),
            'rotated_at'   => $this->rotatedAt?->toIso8601String(),
            'replaced_by'  => $this->replacedBy,
            'revoked_at'   => $this->revokedAt?->toIso8601String(),
            'created_at'   => $this->createdAt?->toIso8601String(),
        ];
    }

    /**
     * An immutable copy of a time, if there is one.
     *
     * @param  ?\Carbon\CarbonInterface  $time
     * @return ?\Carbon\CarbonImmutable
     */
    private static function immutable(?CarbonInterface $time): ?CarbonImmutable
    {
        return $time === null ? null : CarbonImmutable::instance($time);
    }
}
