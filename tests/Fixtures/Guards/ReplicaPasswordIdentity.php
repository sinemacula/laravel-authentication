<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Guards;

use Illuminate\Database\Eloquent\Model;

/**
 * A model over the `password_identities` table on the `replica` connection.
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
