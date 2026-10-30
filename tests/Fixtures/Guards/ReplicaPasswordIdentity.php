<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Guards;

use Illuminate\Database\Eloquent\Model;

/**
 * A model over the `password_identities` table on a `replica` connection: a
 * provider configured with it reads the same table as `PasswordIdentity`, but
 * on another connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReplicaPasswordIdentity extends Model
{
    /** @var string|\UnitEnum|null The connection name for the model. */
    protected $connection = 'replica';

    /** @var string|null The table associated with the model. */
    protected $table = 'password_identities';
}
