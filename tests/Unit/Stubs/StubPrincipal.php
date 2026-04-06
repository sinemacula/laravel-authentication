<?php

declare(strict_types=1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Eloquent stub implementing Principal (and Identity for 2D mode)
 * via the package's ActsAsPrincipal trait.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
class StubPrincipal extends Model implements Identity, Principal
{
    use ActsAsPrincipal;
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
