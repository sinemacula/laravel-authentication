<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Device model whose global scope selects only some columns, leaving out
 * `revoked_at`, so every lookup through the model loads it without the
 * revocation time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PartiallySelectedDevice extends Device
{
    /**
     * Narrow every query to the columns the refresh digest check reads, with
     * the guard and sign-in method every refresh is held to.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::addGlobalScope('refresh_columns', static function (Builder $query): void {
            $query->select(['id', 'authenticatable_type', 'authenticatable_id', 'guard', 'sign_in_method', 'refresh_key']);
        });
    }
}
