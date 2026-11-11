<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Minimal 2D identity with no `HasSessions`, so the package runs without the
 * sessions migration.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class AccessOnlyIdentity extends Model implements Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'access_only_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
