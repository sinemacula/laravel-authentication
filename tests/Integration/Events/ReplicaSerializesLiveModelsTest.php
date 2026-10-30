<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\Concerns\SerializesLiveModels;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\TestCase;

/**
 * Proves a queued event fetches its live models again from the write
 * connection: a model written moments ago, which only the primary holds yet,
 * comes back from a restore rather than reading as gone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(SerializesLiveModels::class)]
final class ReplicaSerializesLiveModelsTest extends TestCase
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
     * A tenant only the primary holds is restored from it.
     *
     * @return void
     */
    public function testALiveModelIsFetchedAgainFromTheWriter(): void
    {
        $tenant = ActivatableTenant::query()->create(['name' => 'Fresh', 'is_active' => true]);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('activatable_tenants')->count());

        $copy = unserialize(serialize(new EventContext('api', new ClientContext(null, null), tenant: $tenant)));

        self::assertInstanceOf(EventContext::class, $copy);
        self::assertInstanceOf(ActivatableTenant::class, $copy->tenant);
        self::assertTrue($tenant->is($copy->tenant));
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
