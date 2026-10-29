<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Plain-object `Tenant` fixture: a tenant that is not an Eloquent model, so its
 * type is its class name.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlainTenantFixture implements Tenant
{
    /**
     * Constructor.
     *
     * @param  int|string  $id
     */
    public function __construct(

        /** Stable identifier of the tenant. */
        public int|string $id,
    ) {}

    /**
     * Return the tenant's stable identifier.
     *
     * @return int|string
     */
    #[\Override]
    public function getTenantIdentifier(): mixed
    {
        return $this->id;
    }
}
