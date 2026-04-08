<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Traits\ActsAsOrganization;

/**
 * Eloquent stub implementing Organization via the package's
 * ActsAsOrganization trait.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
class StubOrganization extends Model implements Organization
{
    use ActsAsOrganization;

    /** @var string|null The table associated with the model. */
    protected $table = 'stub_organizations';

    /** @var array<string> The attributes that aren't mass assignable. */
    protected $guarded = [];
}
