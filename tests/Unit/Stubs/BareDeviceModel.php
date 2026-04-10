<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;

/**
 * Eloquent Device fixture that intentionally does NOT compose the
 * `ActsAsDevice` trait, so it implements every contract method by
 * hand and lacks the trait's `getLastLoggedInName` /
 * `getRefreshKeyName` / `getRevokedAtName` accessors. Used by the
 * `UpdateDeviceTimestamp` listener and the `RefreshTokenExchange`
 * service to exercise their column-name fallback paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @property string $id
 * @property ?string $refresh_key
 * @property ?\Carbon\CarbonInterface $revoked_at
 * @property ?\Carbon\CarbonInterface $last_logged_in_at
 *
 * @internal
 */
final class BareDeviceModel extends Model implements Device
{
    /** @var bool Indicates whether the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string|null The table associated with the model. */
    protected $table = 'bare_devices';

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> Mass-assignment guard list. */
    protected $guarded = [];

    /** @var array<string, string> The attributes that should be cast. */
    protected $casts = [
        'last_logged_in_at' => 'datetime',
        'revoked_at'        => 'datetime',
    ];

    /**
     * Bare device id accessor.
     *
     * @return mixed
     */
    #[\Override]
    public function getDeviceIdentifier(): mixed
    {
        return $this->getAttribute('id');
    }

    /**
     * Last-logged-in accessor reading the bare column directly.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastLoggedIn(): ?CarbonInterface
    {
        $value = $this->getAttribute('last_logged_in_at');

        return $value instanceof CarbonInterface ? $value : null;
    }

    /**
     * Inert MFA verification accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastMfaVerification(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert OS accessor.
     *
     * @return string
     */
    #[\Override]
    public function getOperatingSystem(): string
    {
        return '';
    }

    /**
     * Refresh-key accessor reading the bare column directly.
     *
     * @return ?string
     */
    #[\Override]
    public function getRefreshKey(): ?string
    {
        $value = $this->getAttribute('refresh_key');

        return is_string($value) ? $value : null;
    }

    /**
     * Revoked-at accessor reading the bare column directly.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        $value = $this->getAttribute('revoked_at');

        return $value instanceof CarbonInterface ? $value : null;
    }
}
