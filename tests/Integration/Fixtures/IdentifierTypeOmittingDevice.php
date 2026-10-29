<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Device model whose global scope selects every column but
 * `sign_in_identifier_type`, so every lookup through the model loads it without
 * the type of identifier its session's sign-in used.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class IdentifierTypeOmittingDevice extends Device
{
    /**
     * Narrow every query to the table's columns other than the identifier type.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        self::addGlobalScope('without_identifier_type', static function (Builder $query): void {
            $table = $query->getModel()->getTable();

            $query->select(array_values(array_diff(Schema::getColumnListing($table), ['sign_in_identifier_type'])));
        });
    }
}
