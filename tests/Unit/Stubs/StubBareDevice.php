<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;

/**
 * Eloquent `Device` fixture that intentionally does NOT satisfy the explicit
 * `EloquentDevice` persistence boundary. Used by configuration validation tests
 * to prove refresh and last-use flows fail fast for unsupported Eloquent device
 * implementations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 *
 * @internal
 */
final class StubBareDevice extends Model implements Device
{
    /** @var bool Indicates whether the IDs are auto-incrementing. */
    public $incrementing = false;

    /** @var string|null The table associated with the model. */
    protected $table = 'bare_devices';

    /** @var string The "type" of the primary key ID. */
    protected $keyType = 'string';

    /** @var array<string> Mass-assignment guard list. */
    protected $guarded = [];

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
     * Inert last-use accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getLastUsedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert current refresh digest accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getRefreshKey(): ?string
    {
        return null;
    }

    /**
     * Inert previous refresh digest accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getPreviousRefreshKey(): ?string
    {
        return null;
    }

    /**
     * Inert rotation time accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRefreshRotatedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert idle deadline accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getIdleExpiresAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert absolute deadline accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getAbsoluteExpiresAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert revocation time accessor.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getRevokedAt(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Inert revocation reason accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getRevokedReason(): ?string
    {
        return null;
    }

    /**
     * Inert guard accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getGuard(): ?string
    {
        return null;
    }

    /**
     * Inert sign-in method accessor.
     *
     * @return ?string
     */
    #[\Override]
    public function getSignInMethod(): ?string
    {
        return null;
    }
}
