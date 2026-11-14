<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\ValidatesSessionKey;

/**
 * Check a value against a model's primary key before it is queried, such as a
 * token's `sid` or a stored identity reference's id.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeyShape
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the value has the shape of the model's primary key.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  mixed  $key
     * @return bool
     */
    public static function matches(Model $model, mixed $key): bool
    {
        if ($model instanceof ValidatesSessionKey) {
            return $model->isValidSessionKey($key);
        }

        return match (self::keyFormat($model)) {
            'ulid'    => is_string($key) && Str::isUlid($key),
            'uuid'    => is_string($key) && Str::isUuid($key),
            'integer' => is_int($key) || (is_string($key) && (string) (int) $key === $key),
            default   => is_string($key) && $key !== '',
        };
    }

    /**
     * Classify the model's primary key as `ulid`, `uuid`, `integer`, or
     * `string`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    private static function keyFormat(Model $model): string
    {
        $generated = in_array($model->getKeyName(), $model->uniqueIds(), true);
        $traits    = class_uses_recursive($model);

        return match (true) {
            $generated && in_array(HasUlids::class, $traits, true)   => 'ulid',
            $generated && in_array(HasUuids::class, $traits, true)   => 'uuid',
            in_array($model->getKeyType(), ['int', 'integer'], true) => 'integer',
            default                                                  => 'string',
        };
    }
}
