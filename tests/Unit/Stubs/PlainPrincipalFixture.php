<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;

/**
 * Plain-object `Principal` fixture used by the event serialisation round-trip
 * tests. Intentionally NOT an Eloquent model so the `SerializesModels` trait
 * leaves the instance untouched during serialize.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlainPrincipalFixture implements Principal
{
    /**
     * Constructor.
     *
     * @param  int|string  $id
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  bool  $active
     */
    public function __construct(

        /** Stable identifier used as the `pid` claim. */
        public int|string $id,

        /** Owning identity, if the test wires one explicitly. */
        public ?Identity $identity = null,

        /** Acting tenant, if the test wires one explicitly. */
        public ?Tenant $tenant = null,

        /** Active flag. */
        public bool $active = true,
    ) {}

    /**
     * Return the principal's stable identifier.
     *
     * @return int|string
     */
    #[\Override]
    public function getPrincipalIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Return the identity that owns this principal.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    public function getIdentity(): Identity
    {
        return $this->identity ?? new PlainIdentityFixture($this->id);
    }

    /**
     * Return the tenant the principal acts within, if any.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function getTenant(): ?Tenant
    {
        return $this->tenant;
    }

    /**
     * Return whether the principal is currently active.
     *
     * @return bool
     */
    #[\Override]
    public function isActive(): bool
    {
        return $this->active;
    }
}
