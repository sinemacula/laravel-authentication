<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * 3D principal fixture on the `landlord` connection, acting within no tenant,
 * whose identity (`LandlordPrincipalMember`) lives on the default connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 *
 * @internal
 */
final class LandlordPrincipal extends Model implements Principal
{
    use ActsAsPrincipal;

    /** @var string|\UnitEnum|null The database connection for the model. */
    protected $connection = 'landlord';

    /** @var string|null The table associated with the model. */
    protected $table = 'landlord_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Owning identity relation, on the default connection.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\BelongsTo<\Tests\Integration\Fixtures\LandlordPrincipalMember, covariant $this>
     *
     * @formatter:on
     */
    public function identity(): BelongsTo
    {
        return $this->belongsTo(LandlordPrincipalMember::class, 'identity_id');
    }
}
