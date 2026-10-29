<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D identity on the default connection that records a "tokens valid after"
 * cutoff, in the `cutoff_identities` table the test creates, and whose devices
 * are `SeparateConnectionDevice` rows on their own connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property ?\Carbon\CarbonInterface $tokens_valid_after
 *
 * @internal
 */
final class SeparateConnectionCutoffIdentity extends Model implements HasDevices, HasTokensValidAfter, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesTokensValidAfter;

    /** @var string|null The table associated with the model. */
    protected $table = 'cutoff_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's devices, on the devices' own connection.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return $this->morphMany(SeparateConnectionDevice::class, 'authenticatable');
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return ['tokens_valid_after' => 'datetime'];
    }
}
