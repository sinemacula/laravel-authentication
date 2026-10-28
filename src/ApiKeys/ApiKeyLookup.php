<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\ApiKey;

/**
 * Finds the key a presented public part names and checks the presented secret
 * against it, in one indexed lookup on the write connection, and decides
 * whether the key is still live for a guard.
 *
 * The secret's digest is compared in constant time against the key's, or
 * against a fixed digest no secret has when no key matched, so an unknown
 * public part costs the same work as a wrong secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApiKeyLookup
{
    /** @var string Digest compared against when no key matched; not hex, so no secret's digest equals it. */
    private const string UNMATCHED_DIGEST = 'no-key-has-this-digest-no-key-has-this-digest-no-key-has-this-di';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The key the public part names, read on the write connection, or `null`.
     *
     * @param  string  $public
     * @return ?\SineMacula\Laravel\Authentication\Models\ApiKey
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function find(string $public): ?ApiKey
    {
        /** @var ?\SineMacula\Laravel\Authentication\Models\ApiKey */
        return WriteConnection::query((new ApiKey)->newQuery())->where('prefix', $public)->first();
    }

    /**
     * The key with the id, read on the write connection by its primary key, or
     * `null`; an id that is not a UUID names no key and costs no query.
     *
     * @param  string  $id
     * @return ?\SineMacula\Laravel\Authentication\Models\ApiKey
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function findById(string $id): ?ApiKey
    {
        /** @var ?\SineMacula\Laravel\Authentication\Models\ApiKey */
        return Str::isUuid($id) ? WriteConnection::query((new ApiKey)->newQuery())->whereKey($id)->first() : null;
    }

    /**
     * Whether the secret is the key's, comparing digests in constant time; with
     * no key, the secret's digest is still computed and compared, so the
     * answer, `false`, costs the same.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  string  $secret
     * @return bool
     */
    public static function verifies(?ApiKey $key, #[\SensitiveParameter] string $secret): bool
    {
        return hash_equals($key->secret_hash ?? self::UNMATCHED_DIGEST, ApiKeyToken::digest($secret));
    }

    /**
     * Why the key is not live for the guard at the time, or `null` when it is:
     * another guard's (`credential_guard_mismatch`), revoked
     * (`credential_revoked`), or past its expiry, a rotated key's included,
     * from the second it names (`credential_expired`).
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  string  $guard
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    public static function refusal(ApiKey $key, string $guard, CarbonImmutable $now): ?FailureReason
    {
        return match (true) {
            $key->guard      !== $guard                                                           => FailureReason::CREDENTIAL_GUARD_MISMATCH,
            $key->revoked_at !== null                                                             => FailureReason::CREDENTIAL_REVOKED,
            $key->expires_at !== null && $key->expires_at->getTimestamp() <= $now->getTimestamp() => FailureReason::CREDENTIAL_EXPIRED,
            default                                                                               => null,
        };
    }

    /**
     * Record that the key was used at the time, unless its last use was
     * recorded within the throttle: one conditional update on the key's own
     * connection, mirrored on the instance only when it changed the row, so two
     * requests at once record it once.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function recordUse(ApiKey $key, CarbonImmutable $now): void
    {
        $threshold = $now->subSeconds(ApiKeySettings::lastUsedThrottleSeconds());

        if ($key->last_used_at !== null && $key->last_used_at->getTimestamp() > $threshold->getTimestamp()) {
            return;
        }

        $updated = $key->newQuery()
            ->toBase()
            ->where('id', $key->id)
            ->where(static fn (Builder $query): Builder => $query->whereNull('last_used_at')->orWhere('last_used_at', '<=', $key->fromDateTime($threshold)))
            ->update(['last_used_at' => $key->fromDateTime($now)]);

        if ($updated === 0) {
            return;
        }

        $key->forceFill(['last_used_at' => $now])->syncOriginalAttribute('last_used_at');
    }
}
