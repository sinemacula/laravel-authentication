<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Config\IntegerSetting;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Http\RequestBody;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;

/**
 * What every path that makes a session pending shares: the credential's
 * lifetime, expiry and body field, and how its JSON columns are written.
 *
 * JSON columns bypass the model's casts so cast and uncast models store alike.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PendingState
{
    /** @var string Configuration key of the pending credential's lifetime. */
    public const string TTL_KEY = 'authentication.session.pending_ttl_seconds';

    /** @var string Configuration key of the body field a pending credential is read from. */
    public const string FIELD_KEY = 'authentication.session.pending_credential_field';

    /** @var string Field used when the configuration names none. */
    private const string DEFAULT_FIELD = 'pending_credential';

    /** @var int Lifetime used when the configuration has none, in seconds. */
    private const int DEFAULT_TTL_SECONDS = 300;

    /** @var int Shortest lifetime accepted, in seconds. */
    private const int MIN_TTL_SECONDS = 30;

    /** @var int Longest lifetime accepted, in seconds. */
    private const int MAX_TTL_SECONDS = 3600;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The configured lifetime of a pending credential, in seconds.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function ttlSeconds(Repository $config): int
    {
        return IntegerSetting::read($config, self::TTL_KEY, self::DEFAULT_TTL_SECONDS, self::MIN_TTL_SECONDS, self::MAX_TTL_SECONDS);
    }

    /**
     * The body field the pending credential is read from.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function credentialField(Repository $config): string
    {
        $field = $config->get(self::FIELD_KEY, self::DEFAULT_FIELD);

        if (!RequestBody::isFieldName($field)) {
            throw new \InvalidArgumentException(sprintf('%s must be a field name without `.`, spaces or brackets.', self::FIELD_KEY));
        }

        return $field;
    }

    /**
     * When a pending credential issued at `$now` expires, never past the
     * session's absolute deadline.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @param  int  $ttlSeconds
     * @param  ?\Carbon\CarbonInterface  $absolute
     * @return \Carbon\CarbonImmutable
     */
    public static function expiry(CarbonImmutable $now, int $ttlSeconds, ?CarbonInterface $absolute): CarbonImmutable
    {
        $expiry = $now->addSeconds($ttlSeconds);

        return $absolute !== null && $absolute->getTimestamp() < $expiry->getTimestamp() ? CarbonImmutable::instance($absolute) : $expiry;
    }

    /**
     * The requirements as the session stores them.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @return string
     *
     * @throws \JsonException
     */
    public static function requires(array $requires): string
    {
        return json_encode(array_map(static fn (PendingRequirement $requirement): string => $requirement->value, $requires), JSON_THROW_ON_ERROR);
    }

    /**
     * Set the columns on the unsaved session as stored, bypassing its casts,
     * for the insert to write as they are.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  array<string, mixed>  $values
     * @return void
     */
    public static function fill(EloquentSession&Model $session, array $values): void
    {
        $session->setRawAttributes([...$session->getAttributes(), ...$values]);
    }

    /**
     * Mirror columns an update wrote on the session as persisted state, as
     * stored, bypassing its casts.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  array<string, mixed>  $values
     * @return void
     */
    public static function mirror(EloquentSession&Model $session, array $values): void
    {
        self::fill($session, $values);

        $session->syncOriginalAttributes(array_keys($values));
    }
}
