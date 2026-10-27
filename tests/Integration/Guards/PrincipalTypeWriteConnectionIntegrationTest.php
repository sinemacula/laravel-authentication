<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\PrincipalType;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\TestCase;

/**
 * Proves a principal's type is read from the write connection: a tenant whose
 * type changed on the primary, while the replica still holds the old one, gives
 * its members the primary's type, both when read directly and in the `pty`
 * claim of an access token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalType::class)]
final class PrincipalTypeWriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /**
     * Create the typed tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('typed_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('typed_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('category')->nullable();
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('typed_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id')->nullable();
            $blueprint->string('type')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * The tenant's type comes from the primary although the replica holds an
     * older one, so a member cannot be typed by a lagging replica.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTenantTypeIsReadFromThePrimaryWhileTheReplicaLags(): void
    {
        $membership = $this->seedMembershipInTenantRetypedOnThePrimary();

        self::assertSame('staff', PrincipalType::of($this->reload($membership)));

        $claims = Auth::manager()->jwt('api')->parse(
            Auth::manager()->jwt('api')->issueAccessToken(WriteConnection::during($membership, $membership->getIdentity(...)), $this->reload($membership), null),
            TokenType::ACCESS,
        );

        self::assertIsArray($claims);
        self::assertSame('staff', $claims[Claims::PRINCIPAL_TYPE->value]);
    }

    /**
     * Configure the lagging replica and a guard over the typed identities.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'typed']);
        $config->set('auth.providers.typed', ['driver' => 'model', 'model' => TypedIdentity::class]);
    }

    /**
     * Seed a member of a tenant whose replica row says `customer` while the
     * primary has since moved it to `staff`.
     *
     * @return \Tests\Integration\Fixtures\TypedMembership
     */
    private function seedMembershipInTenantRetypedOnThePrimary(): TypedMembership
    {
        $identity = TypedIdentity::query()->create(['email' => 'lagging@example.test', 'password' => 'unused']);
        $tenant   = TypedTenant::query()->create(['category' => 'customer']);

        $this->copyRowToReplica('typed_tenants', $tenant->getKey());

        $tenant->update(['category' => 'staff']);

        return TypedMembership::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey()]);
    }

    /**
     * Load the membership afresh from the primary, without its tenant, so the
     * tenant is read when the type is.
     *
     * @param  \Tests\Integration\Fixtures\TypedMembership  $membership
     * @return \Tests\Integration\Fixtures\TypedMembership
     */
    private function reload(TypedMembership $membership): TypedMembership
    {
        $fresh = WriteConnection::query(TypedMembership::query())->find($membership->getKey());

        self::assertInstanceOf(TypedMembership::class, $fresh);
        self::assertFalse($fresh->relationLoaded('tenant'));

        return $fresh;
    }
}
