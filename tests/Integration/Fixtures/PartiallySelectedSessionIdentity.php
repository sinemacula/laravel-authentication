<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * 2D identity whose `sessions()` relation leaves out `revoked_at`, keyed by
 * UUID so `authenticatable_id` compares as text.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property string $id
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class PartiallySelectedSessionIdentity extends Model implements HasSessions, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, HasUuids;

    /** @var string|null The table associated with the model. */
    protected $table = 'partially_selected_session_identities';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's sessions, loaded without their revocation column.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Authentication\Models\Session, $this>
     */
    #[\Override]
    public function sessions(): MorphMany
    {
        return $this->morphMany(Session::class, 'authenticatable')
            ->select(['id', 'authenticatable_type', 'authenticatable_id', 'client_name']);
    }
}
