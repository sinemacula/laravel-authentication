<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 2D identity fixture for access-only mode: it holds no devices (no
 * `HasDevices`) and records when its device-less access tokens become valid, in
 * the `access_only_cutoff_identities` table the test creates.
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
final class AccessOnlyCutoffIdentity extends Model implements HasTokensValidAfter, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesTokensValidAfter;

    /** @var string|null The table associated with the model. */
    protected $table = 'access_only_cutoff_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

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
