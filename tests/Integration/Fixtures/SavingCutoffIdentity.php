<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Carbon\CarbonInterface;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * 2D identity with sessions whose own `HasTokensValidAfter` persists its cutoff
 * through `save()`.
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
final class SavingCutoffIdentity extends Model implements HasSessions, HasTokensValidAfter, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'saving_cutoff_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's sessions of the shipped model.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function sessions(): Builder
    {
        return Session::query()
            ->where('authenticatable_type', self::class)
            ->where('authenticatable_id', (string) $this->id);
    }

    /**
     * Return the time at or before which access tokens issued without a session
     * are rejected, or `null` when there is none.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getTokensValidAfter(): ?CarbonInterface
    {
        return $this->tokens_valid_after;
    }

    /**
     * Move the cutoff forward to `$time` and save the model.
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
        return ['tokens_valid_after' => 'datetime'];
    }
}
