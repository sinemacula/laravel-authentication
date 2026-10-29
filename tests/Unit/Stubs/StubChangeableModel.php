<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierChanges;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;

/**
 * Eloquent stub using the default identifier changes, open to subclasses that
 * rename its columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
class StubChangeableModel extends Model implements HasChangeableIdentifiers
{
    use ProvidesIdentifierChanges;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
