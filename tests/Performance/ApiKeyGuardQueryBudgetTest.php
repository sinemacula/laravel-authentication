<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use Tests\Concerns\InteractsWithMachineCredentials;

/**
 * Query-budget contracts for the `api_key` guard: one indexed lookup of the
 * key, then the owner and its principal, a write only when the last use is
 * stale, no password hashing, and the same single lookup for an unknown key as
 * for a wrong secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyGuard::class)]
final class ApiKeyGuardQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithMachineCredentials;

    /**
     * Create the tables, and bind a hasher that fails if it is used.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        $hasher = \Mockery::mock(Hasher::class);
        $hasher->shouldNotReceive('make', 'check', 'needsRehash', 'info');

        $this->app?->instance('hash', $hasher);
        $this->app?->instance(Hasher::class, $hasher);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMachineTables();

        parent::tearDown();
    }

    /**
     * A 2D machine's key costs the key lookup and the owner, plus the last-use
     * write while it is stale; within the throttle it writes nothing.
     *
     * @return void
     */
    public function testAMachinesKeyCostsTheLookupAndTheOwner(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);

        $this->startMachineRequest($issued->key);

        self::assertTrue($this->assertQueryBudget(2, 1, static fn (): bool => PackageAuth::guard('machine')->check()));

        $this->startMachineRequest($issued->key);

        self::assertTrue($this->assertQueryBudget(2, 0, static fn (): bool => PackageAuth::guard('machine')->check()));
    }

    /**
     * A service account's key also costs its membership and the membership's
     * tenant.
     *
     * @return void
     */
    public function testAServiceAccountsKeyCostsItsMembershipAndTenant(): void
    {
        [$account, $membership] = $this->seedAccount();

        $issued = $this->apiKeys('accounts')->issue($account, $membership);

        $this->startMachineRequest($issued->key);

        self::assertTrue($this->assertQueryBudget(4, 1, static fn (): bool => PackageAuth::guard('accounts')->check()));

        $this->startMachineRequest($issued->key);

        self::assertTrue($this->assertQueryBudget(4, 0, static fn (): bool => PackageAuth::guard('accounts')->check()));
    }

    /**
     * A malformed key costs nothing; an unknown key and a wrong secret cost the
     * one lookup each; a revoked key stops after it.
     *
     * @return void
     */
    public function testARefusedKeyCostsAtMostTheLookup(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine);
        $revoked = $this->apiKeys()->issue($machine, $machine);

        $this->apiKeys()->revoke($machine, $revoked->id);

        $presented = [0 => 'not-a-key', 1 => 'ak_zzzzzzzzzzzzzzzz_' . str_repeat('a', 40)];

        foreach ($presented as $reads => $key) {
            $this->startMachineRequest($key);

            self::assertFalse($this->assertQueryBudget($reads, 0, static fn (): bool => PackageAuth::guard('machine')->check()));
        }

        foreach ([$issued->summary->prefix . '_' . str_repeat('a', 40), $revoked->key] as $key) {
            $this->startMachineRequest($key);

            self::assertFalse($this->assertQueryBudget(1, 0, static fn (): bool => PackageAuth::guard('machine')->check()));
        }

        self::assertSame(2, DB::table('api_keys')->count());
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMachineGuards($app->make(ConfigRepository::class));
    }
}
