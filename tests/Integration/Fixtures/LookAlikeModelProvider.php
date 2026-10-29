<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;

/**
 * The `model` provider with the lookup a case- and accent-insensitive collation
 * gives (MySQL's `utf8mb4_unicode_ci`, for one) on every driver: an identity is
 * found by any look-alike of its identifier, such as `alice@examplé.com` for
 * `alice@example.com`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LookAlikeModelProvider extends ModelProvider
{
    /**
     * The first identity whose identifier matches the given one once both have
     * their case and accents folded away, read on the write connection.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        foreach ($this->createModel()::query()->useWritePdo()->orderBy('id')->get() as $candidate) {

            if (self::matches($candidate, $credentials)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Whether every given identifier folds to the candidate's.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $candidate
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    private static function matches(Model $candidate, array $credentials): bool
    {
        foreach ($credentials as $column => $value) {

            $stored = $candidate->getAttribute((string) $column);

            if (!is_string($value) || !is_string($stored) || self::fold($value) !== self::fold($stored)) {
                return false;
            }
        }

        return true;
    }

    /**
     * The value without case or accents.
     *
     * @param  string  $value
     * @return string
     */
    private static function fold(string $value): string
    {
        return Str::lower(Str::ascii($value));
    }
}
