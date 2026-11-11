<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Events;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\MorphClass;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Assertions on the identity, principal, tenant or session an event's context
 * names by type and identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EventContextAssertions
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Assert the context names the identity, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return void
     */
    public static function assertIdentity(?Identity $expected, EventContext $context): void
    {
        Assert::assertSame(self::identityOf($expected), [$context->identityType, $context->identityId]);
    }

    /**
     * Assert the context names the principal, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return void
     */
    public static function assertPrincipal(?Principal $expected, EventContext $context): void
    {
        Assert::assertSame(self::principalOf($expected), [$context->principalType, $context->principalId]);
    }

    /**
     * Assert the context names the tenant, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return void
     */
    public static function assertTenant(?Tenant $expected, EventContext $context): void
    {
        Assert::assertSame(self::tenantOf($expected), [$context->tenantType, $context->tenantId]);
    }

    /**
     * Assert the context names the session, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return void
     */
    public static function assertSession(?Session $expected, EventContext $context): void
    {
        Assert::assertSame(self::sessionOf($expected), $context->sessionId);
    }

    /**
     * Whether the context names the identity, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return bool
     */
    public static function namesIdentity(?Identity $expected, EventContext $context): bool
    {
        return self::identityOf($expected) === [$context->identityType, $context->identityId];
    }

    /**
     * Whether the context names the principal, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return bool
     */
    public static function namesPrincipal(?Principal $expected, EventContext $context): bool
    {
        return self::principalOf($expected) === [$context->principalType, $context->principalId];
    }

    /**
     * Whether the context names the tenant, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return bool
     */
    public static function namesTenant(?Tenant $expected, EventContext $context): bool
    {
        return self::tenantOf($expected) === [$context->tenantType, $context->tenantId];
    }

    /**
     * Whether the context names the session, or none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $expected
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @return bool
     */
    public static function namesSession(?Session $expected, EventContext $context): bool
    {
        return self::sessionOf($expected) === $context->sessionId;
    }

    /**
     * The type and identifier a context names the identity by.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return array{0: ?string, 1: ?string}
     */
    private static function identityOf(?Identity $identity): array
    {
        return $identity === null ? [null, null] : [MorphClass::of($identity), IdentifierCoercion::stringify($identity->getAuthIdentifier())];
    }

    /**
     * The type and identifier a context names the principal by.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return array{0: ?string, 1: ?string}
     */
    private static function principalOf(?Principal $principal): array
    {
        return $principal === null ? [null, null] : [MorphClass::of($principal), PrincipalReference::id($principal)];
    }

    /**
     * The type and identifier a context names the tenant by.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return array{0: ?string, 1: ?string}
     */
    private static function tenantOf(?Tenant $tenant): array
    {
        return $tenant === null ? [null, null] : [MorphClass::of($tenant), IdentifierCoercion::stringify($tenant->getTenantIdentifier())];
    }

    /**
     * The identifier a context names the session by.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?string
     */
    private static function sessionOf(?Session $session): ?string
    {
        return $session === null ? null : IdentifierCoercion::stringify($session->getSessionIdentifier());
    }
}
