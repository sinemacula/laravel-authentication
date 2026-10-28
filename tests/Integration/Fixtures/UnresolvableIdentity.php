<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Misconfigured identity fixture: an `Identity` that is neither a `Principal`
 * nor `HasPrincipals`, so the default resolver cannot resolve a principal for
 * it and throws `UnresolvableIdentityException`.
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
final class UnresolvableIdentity extends Model implements HasDevices, Identity
{
    use Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'unresolvable_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's devices.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return Device::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
