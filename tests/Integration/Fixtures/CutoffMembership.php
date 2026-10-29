<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D principal fixture that records, through `ProvidesTokensValidAfter`, when
 * the access tokens issued without a device for it become valid, owned by an
 * `AccessOnlyMember`, in the `cutoff_memberships` table the test creates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property ?\Carbon\CarbonInterface $tokens_valid_after
 *
 * @internal
 */
final class CutoffMembership extends Model implements HasTokensValidAfter, Principal
{
    use ActsAsPrincipal, ProvidesTokensValidAfter;

    /** @var string|null The table associated with the model. */
    protected $table = 'cutoff_memberships';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Owning identity relation.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\AccessOnlyMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(AccessOnlyMember::class, 'identity_id');
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
