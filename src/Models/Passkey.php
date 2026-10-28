<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;

/**
 * A passkey: a WebAuthn credential an identity signs in with, scoped to the
 * relying party it was registered for. It records the credential's id, public
 * key, sign counter and transports, the user handle it was registered under,
 * its backup state, and when it was last used.
 *
 * Kept on the device model's connection, in the table named by
 * `authentication.passkeys.table`. Passkeys are not pruned: one lasts until its
 * owner removes it.
 *
 * Only the class name is public; its columns and behaviour belong to the
 * passkey service. Read an identity's passkeys through
 * `Auth::passkeys()->passkeys()`, whose summaries carry no key material.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $credential_id_hash
 * @property string $credential_id
 * @property string $authenticatable_type
 * @property string $authenticatable_id
 * @property string $rp_id
 * @property string $user_handle
 * @property string $public_key
 * @property int $sign_count
 * @property list<string> $transports
 * @property ?string $aaguid
 * @property bool $backup_eligible
 * @property bool $backup_state
 * @property bool $uv_initialized
 * @property ?string $name
 * @property ?\Carbon\CarbonInterface $last_used_at
 * @property \Carbon\CarbonInterface $created_at
 * @property \Carbon\CarbonInterface $updated_at
 */
final class Passkey extends Model
{
    /** @var bool Whether the primary key auto-increments. */
    public $incrementing = false;

    /** @var string The type of the primary key. */
    protected $keyType = 'string';

    /** @var list<string> The attributes that are mass assignable: none, every column is written by the passkey service. */
    protected $fillable = [];

    /** @var list<string> The attributes hidden from serialisation. */
    protected $hidden = ['credential_id_hash', 'credential_id', 'user_handle', 'public_key', 'sign_count'];

    /**
     * Create a passkey on the device model's connection, in the configured
     * table. Both are applied here, before Eloquent reads them, so this is
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
        $this->setTable(Config::string('authentication.passkeys.table', 'passkeys'));
        $this->setConnection(DeviceLookup::model()->getConnectionName());

        parent::__construct($attributes);
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
            'sign_count'      => 'integer',
            'transports'      => 'array',
            'backup_eligible' => 'boolean',
            'backup_state'    => 'boolean',
            'uv_initialized'  => 'boolean',
            'last_used_at'    => 'datetime',
        ];
    }
}
