<?php

declare(strict_types = 1);

namespace Tests\Integration\Admission;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\PrincipalAdmission;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for asking the access contracts and tenant resolver on the
 * write connection of a lagging read/write split.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalAdmission::class)]
#[CoversClass(TenantAdmission::class)]
final class PrincipalAdmissionTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Table of the rows the contracts answer from. */
    private const string GRANTS = 'grants';

    /**
     * Create the grants table on the landlord primary and replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica(self::GRANTS, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
        }, self::LANDLORD_PRIMARY_CONNECTION, self::LANDLORD_REPLICA_CONNECTION);
    }

    /**
     * Remove the temporary primary and replica files.
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
     * `ApplicationAccess` is asked with the principal's connection reading from
     * its writer, which reads from its replica again afterwards.
     *
     * @return void
     */
    public function testApplicationAccessIsAskedOnThePrincipalsWriter(): void
    {
        DB::connection(self::LANDLORD_CONNECTION)->table(self::GRANTS)->insert(['id' => 1]);

        $access = new class implements ApplicationAccess {
            /**
             * Whether the principal's connection finds a grant.
             *
             * @param  string  $application
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @return bool
             */
            #[\Override]
            public function mayUse(string $application, Principal $principal): bool
            {
                return DB::connection('landlord')->table('grants')->exists();
            }
        };

        $this->app?->instance(ApplicationAccess::class, $access);

        $principal = self::landlordPrincipal(null);

        self::assertFalse($access->mayUse('api', $principal));
        self::assertTrue(PrincipalAdmission::mayUse('api', $principal));
        self::assertNull(PrincipalAdmission::refusal('api', $principal));
        self::assertFalse($access->mayUse('api', $principal));
    }

    /**
     * `TenantResolver` and `TenantAccess` are asked on the principal's writer.
     *
     * @return void
     */
    public function testTheResolverAndTenantAccessAreAskedOnThePrincipalsWriter(): void
    {
        DB::connection(self::LANDLORD_CONNECTION)->table(self::GRANTS)->insert(['id' => 1]);

        $tenant = new PlainTenantFixture('descendant');
        $found  = static fn (): bool => DB::connection('landlord')->table('grants')->exists();

        $this->app?->instance(TenantResolver::class, new class ($tenant, $found) implements TenantResolver {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
             * @param  \Closure(): bool  $found
             */
            public function __construct(

                /** The tenant the resolver finds. */
                private readonly Tenant $tenant,

                /** Whether the principal's connection finds a grant. */
                private readonly \Closure $found,
            ) {}

            /**
             * The tenant, when the principal's connection finds a grant.
             *
             * @param  string  $tenantId
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
             */
            #[\Override]
            public function resolve(string $tenantId): ?Tenant
            {
                return ($this->found)() ? $this->tenant : null;
            }
        });

        $this->app?->instance(TenantAccess::class, new class ($found) implements TenantAccess {
            /**
             * Constructor.
             *
             * @param  \Closure(): bool  $found
             */
            public function __construct(

                /** Whether the principal's connection finds a grant. */
                private readonly \Closure $found,
            ) {}

            /**
             * Whether the principal's connection finds a grant.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
             * @return bool
             */
            #[\Override]
            public function mayActIn(Principal $principal, ?Tenant $tenant): bool
            {
                return ($this->found)();
            }
        });

        $principal = self::landlordPrincipal(new PlainTenantFixture('own'));

        self::assertFalse($found());
        self::assertSame($tenant, TenantAdmission::select($principal, TenantSelection::of('descendant')));
        self::assertSame($tenant, TenantAdmission::recorded($principal, 'descendant', true));
        self::assertFalse($found());
    }

    /**
     * Read from the replica only, the grant is missing and the principal is
     * refused, as a contract asked outside the package's pin would refuse it.
     *
     * @return void
     */
    public function testWithoutTheGrantThePrincipalIsRefused(): void
    {
        $this->app?->instance(ApplicationAccess::class, new class implements ApplicationAccess {
            /**
             * Whether the principal's connection finds a grant.
             *
             * @param  string  $application
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @return bool
             */
            #[\Override]
            public function mayUse(string $application, Principal $principal): bool
            {
                return DB::connection('landlord')->table('grants')->exists();
            }
        });

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, PrincipalAdmission::refusal('api', self::landlordPrincipal(null)));
    }

    /**
     * Use a lagging landlord split beside the default connection.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingLandlordReplica(app(ConfigRepository::class));
    }

    /**
     * Create no package tables: the tests read only their own.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void {}

    /**
     * A principal stored on the landlord connection, belonging to the tenant.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private static function landlordPrincipal(?Tenant $tenant): StubPrincipal
    {
        $principal = new class extends StubPrincipal {
            /** @var string|\UnitEnum|null The connection the principal is stored on. */
            protected $connection = 'landlord';

            /** @var ?\SineMacula\Laravel\Authentication\Contracts\Tenant The tenant the principal belongs to. */
            public ?Tenant $belongsTo = null;

            /**
             * The tenant the principal belongs to.
             *
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
             */
            #[\Override]
            public function getTenant(): ?Tenant
            {
                return $this->belongsTo;
            }
        };

        $principal->belongsTo = $tenant;

        return $principal;
    }
}
