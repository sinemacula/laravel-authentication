<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySettings;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;

/**
 * An API key: its public part, the digest of its secret, the one guard it
 * authenticates for, the non-human identity that owns it, the one principal it
 * acts as and that principal's tenant, its scopes, and when it was last used,
 * rotated, revoked or expires.
 *
 * Kept on the device model's connection, in the table named by
 * `authentication.api_keys.table`. Keys revoked or expired more than
 * `authentication.api_keys.prune_after_days` ago are pruned by Laravel's
 * `model:prune --model` with this class.
 *
 * Only the class name is public, for applications to schedule that pruning
 * with; its columns and behaviour belong to the API key service and guard.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $public_id
 * @property string $secret_hash
 * @property string $guard
 * @property ?string $name
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $principal_type
 * @property string $principal_id
 * @property ?string $tenant_type
 * @property ?string $tenant_id
 * @property list<string> $scopes
 * @property ?\Carbon\CarbonInterface $expires_at
 * @property ?\Carbon\CarbonInterface $last_used_at
 * @property ?\Carbon\CarbonInterface $rotated_at
 * @property ?string $replaced_by
 * @property ?\Carbon\CarbonInterface $revoked_at
 * @property ?\Carbon\CarbonInterface $created_at
 * @property ?\Carbon\CarbonInterface $updated_at
 */
final class ApiKey extends Model
{
    use MassPrunable;

    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable: none, every column is written by the service. */
    protected $fillable = [];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['secret_hash'];

    /**
     * Create a key on the device model's connection, in the configured table.
     * Both are applied here, before Eloquent reads them, so this is
     * construction rather than model behaviour.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.api_keys.table', 'api_keys'));
        $this->setConnection(DeviceLookup::model()->getConnectionName());

        parent::__construct($attributes);
    }

    /**
     * The keys revoked, or expired, more than the retention ago: a rotated key
     * expires when its overlap ends, so it is pruned that long after.
     *
     * @return \Illuminate\Database\Eloquent\Builder<self>
     *
     * @throws \InvalidArgumentException
     */
    public function prunable(): Builder
    {
        $cutoff = $this->fromDateTime(Carbon::now()->subDays(ApiKeySettings::pruneAfterDays()));

        return self::query()->where('revoked_at', '<=', $cutoff)->orWhere('expires_at', '<=', $cutoff);
    }

    /**
     * The attributes that should be cast.
     *
     * @return array<string, string>
     */
    #[\Override]
    protected function casts(): array
    {
        return [
            'scopes'       => 'array',
            'expires_at'   => 'datetime',
            'last_used_at' => 'datetime',
            'rotated_at'   => 'datetime',
            'revoked_at'   => 'datetime',
        ];
    }
}
