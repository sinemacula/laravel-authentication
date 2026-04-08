<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Traits\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Minimal 2D identity used by the access-only integration test.
 *
 * Deliberately does NOT implement `HasDevices` or touch the shipped
 * `Device` model, verifying the package works end-to-end without the
 * devices migration present.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @property int $id
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class AccessOnlyIdentity extends Model implements Identity, Principal
{
    use ActsAsPrincipal;
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'access_only_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
