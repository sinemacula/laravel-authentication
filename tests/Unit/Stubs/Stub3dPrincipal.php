<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Eloquent stub implementing Principal via the ActsAsPrincipal trait without
 * also implementing Identity. Exercises the 3D code path where the identity
 * relation must be loaded explicitly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
class Stub3dPrincipal extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
