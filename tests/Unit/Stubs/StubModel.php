<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * Lightweight Eloquent stub used by service-provider tests where a minimal
 * model is enough.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubModel extends Model
{
    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
