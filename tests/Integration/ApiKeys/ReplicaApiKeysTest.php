<?php

declare(strict_types = 1);

namespace Tests\Integration\ApiKeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Events\ApiKeyRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\MachineClient;
use Tests\Integration\Fixtures\MachineMembership;
use Tests\TestCase;

/**
 * Proves every read that decides an API key is from the write connection: a key
 * issued, revoked or rotated moments ago, which only the primary holds yet, is
 * accepted or refused as the primary says by the `api_key` guard, the client
 * credentials exchange and the bearer path of the tokens it issues, and the
 * service finds it; a principal's tenant changed moments ago is the one a new
 * key records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyLookup::class)]
#[CoversClass(ApiKeyService::class)]
#[CoversClass(ClientCredentialsExchange::class)]
final class ReplicaApiKeysTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithMachineCredentials;

    /** @var \Tests\Integration\Fixtures\MachineClient The machine client, as both copies hold it. */
    private MachineClient $machine;

    /**
     * Freeze the clock, create the machine tables on the primary and the
     * replica, and seed a machine client both hold.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createOnPrimaryAndReplica('machine_clients', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('machine_accounts', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('machine_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('account_id');
            $blueprint->string('tenant_type')->default(ActivatableTenant::class);
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->string('type')->default('service');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        $this->machine = $this->seedMachine();

        $this->copyRowToReplica('machine_clients', $this->machine->getKey());
    }

    /**
     * Release the clock and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::releaseMachineClock();

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A key only the primary holds authenticates its request and is found,
     * listed and revoked by the service; once revoked on the primary, while the
     * replica still holds it live, it is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApiKeyGuardAndTheServiceReadTheKeyOnThePrimary(): void
    {
        $issued = $this->apiKeys()->issue($this->machine, $this->machine, ['read']);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('api_keys')->count());
        self::assertTrue($this->authenticates('machine', $issued->key()));
        self::assertSame($issued->id, $this->apiKeys()->find($this->machine, $issued->id)?->id);
        self::assertCount(1, $this->apiKeys()->keys($this->machine));

        $this->copyRowToReplica('api_keys', $issued->id);

        self::assertTrue($this->apiKeys()->revoke($this->machine, $issued->id));
        self::assertNull(DB::connection(self::REPLICA_CONNECTION)->table('api_keys')->value('revoked_at'));
        self::assertFalse($this->authenticates('machine', $issued->key()));
    }

    /**
     * A key only the primary holds is rotated, and its replacement, which only
     * the primary holds too, authenticates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyOnlyThePrimaryHoldsRotates(): void
    {
        $issued  = $this->apiKeys()->issue($this->machine, $this->machine);
        $rotated = $this->apiKeys()->rotate($this->machine, $issued->id, 0);

        self::assertNotNull($rotated);
        self::assertTrue($this->authenticates('machine', $rotated->key()));
        self::assertFalse($this->authenticates('machine', $issued->key()));
    }

    /**
     * A key only the primary holds is exchanged for a token, which works on its
     * guard; once the key is revoked on the primary, while the replica still
     * holds it live, the token is refused at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheExchangeAndItsTokensReadTheKeyOnThePrimary(): void
    {
        $issued = $this->apiKeys('m2m')->issue($this->machine, $this->machine, ['read']);

        $this->startMachineRequest();

        $result = Auth::clientCredentials('m2m')->exchange($issued->summary->publicId, substr($issued->key(), 20));

        self::assertTrue($result->isGranted());
        self::assertNotNull($result->accessToken);
        self::assertTrue($this->authenticates('m2m', $result->accessToken));

        $this->copyRowToReplica('api_keys', $issued->id);

        self::assertTrue($this->apiKeys('m2m')->revoke($this->machine, $issued->id));
        self::assertFalse($this->authenticates('m2m', $result->accessToken));
    }

    /**
     * A key records the principal's tenant as the primary holds it, and the
     * key's revocation reports it: a membership moved moments ago to a tenant
     * only the primary holds yet.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyRecordsTheTenantThePrimaryHolds(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $this->copyRowToReplica('machine_accounts', $account->getKey());
        $this->copyRowToReplica('machine_memberships', $membership->getKey());
        $this->copyRowToReplica('activatable_tenants', $tenant->getKey());

        $moved = ActivatableTenant::query()->create(['name' => 'Moved', 'is_active' => true]);

        DB::connection(self::PRIMARY_CONNECTION)->table('machine_memberships')->update(['tenant_id' => $moved->getKey()]);

        $current = MachineMembership::query()->useWritePdo()->findOrFail($membership->getKey());
        $issued  = $this->apiKeys('accounts')->issue($account, $current);

        $recorded = DB::connection(self::PRIMARY_CONNECTION)->table('api_keys')->where('id', $issued->id)->value('tenant_id');

        self::assertSame(IdentifierCoercion::stringify($moved->getKey()), $recorded);

        $this->recordMachineEvents([ApiKeyRevoked::class]);

        self::assertTrue($this->apiKeys('accounts')->revoke($current, $issued->id));
        self::assertTrue($moved->is($this->machineEventsOf(ApiKeyRevoked::class)[0]->context->tenant));
    }

    /**
     * Configure the guards over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureMachineGuards($config);

        $this->configureLaggingReplica($config);
    }

    /**
     * Create the package tables, the API keys table among them, on the primary
     * and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();

        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager   = app(DatabaseManager::class);
        $migration = require __DIR__ . '/../../../database/migrations/2026_04_06_000006_create_api_keys_table.php';

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            $manager->setDefaultConnection($connection);
            $migration->up();
        }

        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }

    /**
     * Whether a request bearing the credential authenticates on the guard.
     *
     * @param  string  $guard
     * @param  string  $credential
     * @return bool
     */
    private function authenticates(string $guard, string $credential): bool
    {
        $this->startMachineRequest($credential);

        return Auth::guard($guard)->check();
    }
}
