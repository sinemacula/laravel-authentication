<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\ValidatesSessionKey;

/**
 * Check a `sid` claim against the session model's key before it is queried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SessionKeyShape
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the value has the shape of the session model's primary key.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @param  mixed  $key
     * @return bool
     */
    public static function matches(Model $session, mixed $key): bool
    {
        if ($session instanceof ValidatesSessionKey) {
            return $session->isValidSessionKey($key);
        }

        return match (self::keyFormat($session)) {
            'ulid'    => is_string($key) && Str::isUlid($key),
            'uuid'    => is_string($key) && Str::isUuid($key),
            'integer' => is_int($key) || (is_string($key) && (string) (int) $key === $key),
            default   => is_string($key) && $key !== '',
        };
    }

    /**
     * Classify the session model's primary key as `ulid`, `uuid`, `integer`, or
     * `string`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return string
     */
    private static function keyFormat(Model $session): string
    {
        $generated = in_array($session->getKeyName(), $session->uniqueIds(), true);
        $traits    = class_uses_recursive($session);

        return match (true) {
            $generated && in_array(HasUlids::class, $traits, true)     => 'ulid',
            $generated && in_array(HasUuids::class, $traits, true)     => 'uuid',
            in_array($session->getKeyType(), ['int', 'integer'], true) => 'integer',
            default                                                    => 'string',
        };
    }
}
