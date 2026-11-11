<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Database\Eloquent\Builder as BuilderContract;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ActsAsPrincipal;
use SineMacula\Laravel\Authentication\Concerns\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Eloquent principal, and identity in 2D mode, using ActsAsPrincipal and
 * holding sessions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property string $email
 * @property string $password
 * @property bool $is_active
 *
 * @internal
 *
 * @inheritable
 */
class StubPrincipal extends Model implements HasSessions, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_principals';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];

    /**
     * Eloquent relation builder for the identity's sessions, filtered by the
     * polymorphic `authenticatable_*` columns on the shipped Session model.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function sessions(): BuilderContract
    {
        return Session::query()
            ->where('authenticatable_type', static::class)
            ->where('authenticatable_id', (string) $this->getKey()); // @phpstan-ignore cast.string
    }
}
