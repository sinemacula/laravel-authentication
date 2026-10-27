<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;

/**
 * Eloquent stub using the default identifier verification, open to subclasses
 * that rename its columns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
class StubVerifiableModel extends Model implements HasVerifiableIdentifiers
{
    use ProvidesIdentifierVerification;

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
