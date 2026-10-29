<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * A principal model keyed by a UUID, for devices whose principal column must
 * hold a non-integer key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class UuidKeyedPrincipal extends Model
{
    use HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'uuid_keyed_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
