<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;

/**
 * An ordinary model a user belongs to, which implements neither `Tenant` nor
 * `CanBeActive`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PlainTeam extends Model
{
    /** @var string|null The table associated with the model. */
    protected $table = 'plain_teams';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
