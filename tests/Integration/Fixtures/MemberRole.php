<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Model;

/**
 * A member's role, stored under a `kind`, of which `MemberRoleMembership` reads
 * only the memberships as principals.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @property int $id
 * @property int $identity_id
 * @property string $kind
 *
 * @internal
 */
final class MemberRole extends Model
{
    /** @var string|null The table associated with the model. */
    protected $table = 'member_roles';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
