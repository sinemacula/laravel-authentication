<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySettings;
use SineMacula\Laravel\Authentication\Database\StorageConnection;

/**
 * An API key a non-human identity authenticates with, pruned by `model:prune`
 * once revoked or expired past the retention.
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
     * Create a key on the storage connection, in the configured table.
     *
     * @param  array<string, mixed>  $attributes
     *
     * @throws \InvalidArgumentException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    public function __construct(array $attributes = [])
    {
        $this->setTable(Config::string('authentication.api_keys.table', 'api_keys'));
        $this->setConnection(StorageConnection::name());

        parent::__construct($attributes);
    }

    /**
     * The keys revoked, or expired, more than the retention ago.
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
