<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;

/**
 * An identity row in `integration_identities` whose model names its connection,
 * `testing`, rather than leaving it to whoever relates to it, so a device on
 * another connection still loads it from there.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class NamedConnectionIdentity extends Model
{
    /** @var string|\UnitEnum|null The connection name for the model. */
    protected $connection = 'testing';

    /** @var string|null The table associated with the model. */
    protected $table = 'integration_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
