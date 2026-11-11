<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\TestCase;

/**
 * Tests that a queued event restores without reading the database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
final class ReplicaEventContextTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /**
     * Create the tenants table on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
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
     * An event about a tenant only the primary holds restores without a query.
     *
     * @return void
     */
    public function testAnEventRestoresWithoutAQuery(): void
    {
        $tenant = ActivatableTenant::query()->create(['name' => 'Fresh', 'is_active' => true]);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('activatable_tenants')->count());

        $event   = new SessionRevoked(new EventContext('api', new ClientContext(null, null), tenant: $tenant), RevocationReason::REVOKED);
        $payload = serialize($event);
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $copy = unserialize($payload);

        self::assertInstanceOf(SessionRevoked::class, $copy);
        self::assertEquals($event, $copy);
        self::assertSame([ActivatableTenant::class, IdentifierCoercion::stringify($tenant->getKey())], [$copy->context->tenantType, $copy->context->tenantId]);
        self::assertSame(0, $queries);
    }

    /**
     * Make the lagging split connection the default.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $this->configureLaggingReplica(app(ConfigRepository::class));
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }
}
