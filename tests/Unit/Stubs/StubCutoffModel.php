<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;

/**
 * Eloquent stub that records a "tokens valid after" cutoff in the default
 * column, without a cast, for reading it without a database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
class StubCutoffModel extends Model implements HasTokensValidAfter
{
    use ProvidesTokensValidAfter;

    /** @var string|null The storage format of the model's date columns. */
    protected $dateFormat = 'Y-m-d H:i:s';
}
