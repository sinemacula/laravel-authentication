<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * 2D identity whose `sessions()` relation is limited to those a
 * `session_grants` row permits, read while the relation is built.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 *
 * @internal
 */
final class GrantedSessionsIdentity extends Model implements HasSessions, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * The identity's sessions that a `session_grants` row still permits.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany<\SineMacula\Laravel\Authentication\Models\Session, $this>
     */
    #[\Override]
    public function sessions(): MorphMany
    {
        $granted = $this->getConnection()
            ->table('session_grants')
            ->where('identity_id', $this->getKey())
            ->pluck('session_id')
            ->all();

        return $this->morphMany(Session::class, 'authenticatable')->whereIn('id', $granted);
    }
}
