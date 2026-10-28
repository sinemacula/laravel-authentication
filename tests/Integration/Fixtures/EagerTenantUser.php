<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D fixture that eager-loads the tenant it acts within on every query, so the
 * tenant behind the activity check is loaded alongside the identity lookup
 * rather than lazily.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property int $tenant_id
 *
 * @internal
 */
final class EagerTenantUser extends Model implements Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'eager_tenant_users';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /** @var list<string> The relations to eager load on every query. */
    protected $with = ['tenant'];

    /**
     * Acting tenant relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\ActivatableTenant, covariant $this>
     *
     * @formatter:on
     */
    public function tenant(): BelongsTo
    {
        return $this->belongsTo(ActivatableTenant::class, 'tenant_id');
    }
}
