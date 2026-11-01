<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineCredentials;

/**
 * Query-budget contracts for the client credentials exchange and the bearer
 * path of its tokens: an exchange costs the limiter's check, the key and its
 * owner, and the last-use write; a refused client the same lookups and its
 * counted failure, with no password hashing either way; and a client token
 * costs one query more than any session-less access token, its key read by its
 * primary key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientCredentialsExchange::class)]
#[CoversClass(BearerAuthentication::class)]
final class ClientCredentialsQueryBudgetTest extends PerformanceContractTestCase
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
     * A granted exchange reads the client's limits, the key and its owner, and
     * writes the key's last use; an unknown client reads the limits and looks
     * once for a key, and counts its failure against the IP address (an update,
     * then an insert for a new window; the client id is not counted by
     * default); a wrong secret for a known client costs exactly the same and is
     * answered the same.
     *
     * @return void
     */
    public function testAnExchangeCostsTheLimitsTheKeyAndItsOwner(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys('m2m')->issue($machine, $machine);

        $public = $issued->summary->publicId;
        $secret = substr($issued->key(), 20);

        $this->startMachineRequest();

        $granted = $this->assertQueryBudget(3, 1, static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange($public, $secret));

        self::assertTrue($granted->isGranted());

        $this->startMachineRequest();

        $wrong   = str_repeat('a', 40);
        $refused = $this->assertQueryBudget(2, 2, static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange('ak_zzzzzzzzzzzzzzzz', $wrong));

        self::assertSame('invalid_client', $refused->error);

        DB::table('rate_limits')->delete();

        $this->startMachineRequest();

        $mistaken = $this->assertQueryBudget(2, 2, static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange($public, $wrong));

        self::assertSame($refused->toArray(), $mistaken->toArray());
    }

    /**
     * A service account's exchange also costs its membership and the
     * membership's tenant, each read once: the token's check that the tenant is
     * the principal's own reads the tenant the admission loaded, not the
     * database.
     *
     * @return void
     */
    public function testAServiceAccountsExchangeAlsoCostsItsMembershipAndTenant(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('m2m_accounts')->issue($account, $membership);
        $public = $issued->summary->publicId;
        $secret = substr($issued->key(), 20);

        $this->startMachineRequest();

        $granted = $this->assertQueryBudget(5, 1, static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m_accounts')->exchange($public, $secret));
        $claims  = PackageAuth::manager()->jwt('m2m_accounts')->parse((string) $granted->accessToken);

        self::assertTrue($granted->isGranted());
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $claims[Claims::TENANT_ID->value] ?? null);
    }

    /**
     * A client token costs the key, read by its primary key, and its owner, one
     * query more than a session-less access token, and writes nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientTokenCostsOneQueryMoreThanASessionlessToken(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys('m2m')->issue($machine, $machine);

        $this->startMachineRequest();

        $token = PackageAuth::clientCredentials('m2m')->exchange($issued->summary->publicId, substr($issued->key(), 20))->accessToken;

        self::assertNotNull($token);

        $this->startMachineRequest($token);

        self::assertTrue($this->assertQueryBudget(2, 0, static fn (): bool => PackageAuth::guard('m2m')->check()));
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
