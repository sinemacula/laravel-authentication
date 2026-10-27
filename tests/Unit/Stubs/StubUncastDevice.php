<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use SineMacula\Laravel\Authentication\Concerns\ActsAsDevice;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;

/**
 * Eloquent device using `ActsAsDevice` with no casts, so every attribute holds
 * exactly the value it was given, as a raw database value or an object.
 *
 * Non-`final` so tests can override a column-name accessor in an anonymous
 * subclass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @inheritable
 */
class StubUncastDevice extends Model implements EloquentDevice
{
    use ActsAsDevice;

    /** @var string|null The storage format of the model's date columns. */
    protected $dateFormat = 'Y-m-d H:i:s';

    /**
     * Polymorphic relation to the owning authenticatable identity.
     *
     * @formatter:off
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo<\Illuminate\Database\Eloquent\Model, \Illuminate\Database\Eloquent\Model>
     *
     * @formatter:on
     */
    #[\Override]
    public function authenticatable(): MorphTo
    {
        return $this->morphTo(); // @phpstan-ignore return.type
    }
}
