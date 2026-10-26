<?php

declare(strict_types = 1);

namespace Tests\Performance\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Minimal active 2D identity for performance-contract testing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class PerformanceAccessOnlyIdentity extends Model implements Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'access_only_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * This fixture is always active.
     *
     * @return bool
     */
    #[\Override]
    public function isActive(): bool
    {
        return true;
    }
}
