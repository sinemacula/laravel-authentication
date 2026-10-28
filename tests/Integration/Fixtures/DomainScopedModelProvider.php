<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Model provider over `StubPrincipal` that serves only identities whose email
 * belongs to one domain.
 *
 * Stands in for an application provider that scopes identity lookups (for
 * example to one tenant or audience), so tests can prove the refresh path
 * reloads the device owner through the guard's provider and honours that scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DomainScopedModelProvider extends ModelProvider
{
    /** @var string Email domain the provider serves, including the `@`. */
    public const string DOMAIN = '@customer.test';

    /**
     * Retrieve an identity by its identifier, only when it belongs to the
     * served domain.
     *
     * @param  mixed  $identifier
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveById(mixed $identifier): ?Authenticatable
    {
        $identity = parent::retrieveById($identifier);

        return $identity instanceof StubPrincipal && str_ends_with($identity->email, self::DOMAIN) ? $identity : null;
    }
}
