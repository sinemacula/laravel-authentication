<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;

/**
 * The one-time code table as the engine reads and writes it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CodeRows
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The key's row as stored, read from the write PDO, locked until the
     * transaction ends when asked to, or `null`.
     *
     * @param  string  $digest
     * @param  bool  $lock
     * @return ?\SineMacula\Laravel\Authentication\Models\OneTimeCode
     *
     * @throws \InvalidArgumentException
     */
    public static function find(string $digest, bool $lock = false): ?OneTimeCode
    {
        $query = WriteConnection::query((new OneTimeCode)->newQuery());

        $code = ($lock ? $query->lockForUpdate() : $query)->find($digest);

        return $code instanceof OneTimeCode ? $code : null;
    }

    /**
     * The key's row when its code can still be checked, or why not.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Models\OneTimeCode  $row
     * @param  int  $max
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck|\SineMacula\Laravel\Authentication\Models\OneTimeCode
     */
    public static function live(?OneTimeCode $row, int $max, CarbonImmutable $now): CodeCheck|OneTimeCode
    {
        return match (true) {
            $row === null                                            => CodeCheck::NOT_FOUND,
            $row->consumed_at !== null                               => CodeCheck::USED,
            $row->expires_at->getTimestamp() <= $now->getTimestamp() => CodeCheck::EXPIRED,
            $row->attempts >= $max                                   => CodeCheck::EXHAUSTED,
            default                                                  => $row,
        };
    }

    /**
     * Whether the stored transaction digest is the one given: both absent, or
     * both the same digest.
     *
     * @param  ?string  $stored
     * @param  ?string  $given
     * @return bool
     */
    public static function isSameContext(?string $stored, ?string $given): bool
    {
        return $stored === null || $given === null ? $stored === $given : hash_equals($stored, $given);
    }

    /**
     * A query on the codes' table, on its own connection, for the writes.
     *
     * @return \Illuminate\Database\Query\Builder
     *
     * @throws \InvalidArgumentException
     */
    public static function table(): Builder
    {
        $model = new OneTimeCode;

        return $model->getConnection()->table($model->getTable());
    }
}
