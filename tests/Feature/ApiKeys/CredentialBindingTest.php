<?php

declare(strict_types = 1);

namespace Tests\Feature\ApiKeys;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ApiKeys\CredentialBinding;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Models\ApiKey;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubTenant;

/**
 * Feature tests for the binding every machine credential is held to: the
 * owner's, the principal's and the tenant's type and identifier must all be
 * what was loaded, identifiers alone never sufficing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CredentialBinding::class)]
final class CredentialBindingTest extends TestCase
{
    /**
     * Forget any morph map a test registered.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * A key bound to exactly what loaded passes, identifiers compared as
     * strings.
     *
     * @return void
     */
    public function testAcceptsTheExactOwnerPrincipalAndTenant(): void
    {
        $key = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', StubTenant::class, '3');

        self::assertNull(CredentialBinding::refusal($key, new PlainIdentityFixture(7), new PlainPrincipalFixture(42), self::tenant(3)));
        $untenanted = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', null, null);

        self::assertNull(CredentialBinding::refusal($untenanted, new PlainIdentityFixture('7'), new PlainPrincipalFixture('42'), null));
    }

    /**
     * Another owner, by type or identifier, is `credential_invalid`.
     *
     * @return void
     */
    public function testRefusesAnotherOwner(): void
    {
        $key = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', null, null);

        self::assertSame(FailureReason::CREDENTIAL_INVALID, CredentialBinding::refusal($key, new PlainIdentityFixture(8), new PlainPrincipalFixture(42), null));
        self::assertSame(FailureReason::CREDENTIAL_INVALID, CredentialBinding::refusal($key, self::eloquentIdentity(7), new PlainPrincipalFixture(42), null));
    }

    /**
     * Another principal, by type or identifier, or another tenant, by type or
     * identifier, or a tenant where none was recorded and none where one was,
     * is `principal_mismatch`.
     *
     * @return void
     */
    public function testRefusesAnotherPrincipalOrTenant(): void
    {
        $identity   = new PlainIdentityFixture(7);
        $tenanted   = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', StubTenant::class, '3');
        $untenanted = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', null, null);
        $otherType  = self::key(PlainIdentityFixture::class, '7', StubTenant::class, '42', null, null);
        $typeOnly   = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', StubTenant::class, null);

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($tenanted, $identity, new PlainPrincipalFixture(43), self::tenant(3)));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($otherType, $identity, new PlainPrincipalFixture(42), null));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($tenanted, $identity, new PlainPrincipalFixture(42), self::tenant(4)));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($tenanted, $identity, new PlainPrincipalFixture(42), new PlainTenantFixture(3)));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($typeOnly, $identity, new PlainPrincipalFixture(42), null));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($tenanted, $identity, new PlainPrincipalFixture(42), null));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($untenanted, $identity, new PlainPrincipalFixture(42), self::tenant(3)));
    }

    /**
     * An Eloquent owner is recorded by its morph class, any other by its class
     * name.
     *
     * @return void
     */
    public function testRecordsAnOwnersType(): void
    {
        $eloquent = self::eloquentIdentity(7);

        self::assertSame($eloquent->getMorphClass(), CredentialBinding::ownerType($eloquent));
        self::assertSame(PlainIdentityFixture::class, CredentialBinding::ownerType(new PlainIdentityFixture(7)));
        self::assertTrue(CredentialBinding::isOwnedBy(self::key($eloquent->getMorphClass(), '7', PlainPrincipalFixture::class, '1', null, null), $eloquent));
    }

    /**
     * An Eloquent tenant is recorded by its morph class, any other by its class
     * name, and no tenant as none; a key recording a tenant's alias passes for
     * that tenant.
     *
     * @return void
     */
    public function testRecordsATenantsType(): void
    {
        Relation::morphMap(['workspace' => StubTenant::class]);

        self::assertSame('workspace', CredentialBinding::tenantType(self::tenant(3)));
        self::assertSame(PlainTenantFixture::class, CredentialBinding::tenantType(new PlainTenantFixture(3)));
        self::assertNull(CredentialBinding::tenantType(null));

        $aliased = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', 'workspace', '3');
        $named   = self::key(PlainIdentityFixture::class, '7', PlainPrincipalFixture::class, '42', StubTenant::class, '3');

        self::assertNull(CredentialBinding::refusal($aliased, new PlainIdentityFixture(7), new PlainPrincipalFixture(42), self::tenant(3)));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, CredentialBinding::refusal($named, new PlainIdentityFixture(7), new PlainPrincipalFixture(42), self::tenant(3)));
    }

    /**
     * A key recording the owner, principal and tenant.
     *
     * @param  string  $ownerType
     * @param  string  $ownerId
     * @param  string  $principalType
     * @param  string  $principalId
     * @param  ?string  $tenantType
     * @param  ?string  $tenantId
     * @return \SineMacula\Laravel\Authentication\Models\ApiKey
     */
    private static function key(string $ownerType, string $ownerId, string $principalType, string $principalId, ?string $tenantType, ?string $tenantId): ApiKey
    {
        return (new ApiKey)->forceFill([
            'authenticatable_type' => $ownerType,
            'authenticatable_id'   => $ownerId,
            'principal_type'       => $principalType,
            'principal_id'         => $principalId,
            'tenant_type'          => $tenantType,
            'tenant_id'            => $tenantId,
        ]);
    }

    /**
     * An unsaved Eloquent identity with the key.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubIdentity
     */
    private static function eloquentIdentity(int $id): StubIdentity
    {
        $identity = new StubIdentity;

        $identity->forceFill(['id' => $id]);

        return $identity;
    }

    /**
     * An unsaved tenant with the key.
     *
     * @param  int  $id
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private static function tenant(int $id): StubTenant
    {
        $tenant = new StubTenant;

        $tenant->forceFill(['id' => $id]);

        return $tenant;
    }
}
