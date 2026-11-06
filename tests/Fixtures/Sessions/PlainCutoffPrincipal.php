<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * A principal that is no Eloquent model and records a "tokens valid after"
 * cutoff it never moves: a stand-in for an application's principal kept
 * elsewhere than a model's row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlainCutoffPrincipal implements HasTokensValidAfter, Principal
{
    /**
     * Constructor.
     *
     * @param  int|string  $id
     */
    public function __construct(

        /** The principal's identifier. */
        public int|string $id,
    ) {}

    /**
     * Return the principal's identifier.
     *
     * @return int|string
     */
    #[\Override]
    public function getPrincipalIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Return a plain identity of the same identifier.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    public function getIdentity(): Identity
    {
        return new PlainIdentityFixture($this->id);
    }

    /**
     * Return no tenant.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    #[\Override]
    public function getTenant(): ?Tenant
    {
        return null;
    }

    /**
     * Return the cutoff, which it has none of.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getTokensValidAfter(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Move nothing.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function invalidateTokensIssuedBefore(CarbonInterface $time): bool
    {
        unset($time);

        return false;
    }
}
