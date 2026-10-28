<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * A 2D identity that records from when its access tokens issued without a
 * device are valid, in its own `tokens_valid_after` column, as an application
 * implements `HasTokensValidAfter`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property ?\Carbon\CarbonInterface $tokens_valid_after
 *
 * @internal
 */
final class CutoffIdentity extends Model implements HasDevices, HasTokensValidAfter, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'cutoff_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's devices.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function devices(): Builder
    {
        return Device::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }

    /**
     * The recorded time, or `null`.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getTokensValidAfter(): ?CarbonInterface
    {
        return $this->tokens_valid_after;
    }

    /**
     * Move the recorded time forward to the given one.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function invalidateTokensIssuedBefore(CarbonInterface $time): bool
    {
        if ($this->tokens_valid_after !== null && $this->tokens_valid_after->greaterThanOrEqualTo($time)) {
            return false;
        }

        return $this->forceFill(['tokens_valid_after' => $time])->save();
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
            'tokens_valid_after' => 'datetime',
        ];
    }
}
