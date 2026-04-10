<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Eloquent fixture for the 2D guard coexistence test.
 *
 * Implements both `Identity` and `Principal` so the default principal
 * resolver's 2D branch returns the identity itself - i.e. the authenticated
 * identity IS the acting principal. Used by the
 * `GuardCoexistenceIntegrationTest` alongside its 3D counterpart to prove that
 * two package guards configured against different model shapes can coexist in
 * the same Laravel application without cross-contamination.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $is_active
 *
 * @internal
 */
final class Coexist2dIdentity extends Model implements Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'coexist_2d_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'is_active' => 'boolean',
    ];
}
