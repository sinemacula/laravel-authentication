<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Eloquent\Model;

/**
 * Compares what the package hands back, typed by its contracts, with the
 * Eloquent model a test expects, and reads a model's key as the package's
 * contracts take it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ComparesModels
{
    /**
     * Assert that the value is the model expected: an Eloquent model of the
     * same table, connection and key.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $expected
     * @param  mixed  $actual
     * @param  string  $message
     * @return void
     */
    protected static function assertIsModel(Model $expected, mixed $actual, string $message = ''): void
    {
        self::assertInstanceOf(Model::class, $actual, $message);
        self::assertTrue($expected->is($actual), $message);
    }

    /**
     * The model's key, failing the test unless it is an integer or a string.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return int|string
     */
    protected static function modelKey(Model $model): int|string
    {
        $key = $model->getKey();

        if (!is_int($key) && !is_string($key)) {
            self::fail(sprintf('The %s has no integer or string key.', $model::class));
        }

        return $key;
    }
}
