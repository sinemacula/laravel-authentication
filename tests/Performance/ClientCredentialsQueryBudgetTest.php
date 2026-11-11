<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsRequest;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineCredentials;

/**
 * Query-budget contracts for the client credentials exchange and the bearer
 * path of its tokens.
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
     * A granted exchange costs the limits, the key, its owner and the last-use
     * write; a refused one costs the same lookups and its count.
     *
     * @return void
     */
    public function testAnExchangeCostsTheLimitsTheKeyAndItsOwner(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys('m2m')->issue($machine, $machine);

        $public = $issued->summary->publicId;
        $secret = substr($issued->key()->reveal(), 20);

        $this->startMachineRequest();

        $granted = $this->assertQueryBudget(
            3,
            1,
            static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange(self::basicClient($public, $secret), self::requestClient()),
        );

        self::assertTrue($granted->isGranted());

        $this->startMachineRequest();

        $wrong   = str_repeat('a', 40);
        $refused = $this->assertQueryBudget(
            2,
            2,
            static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange(self::basicClient('ak_zzzzzzzzzzzzzzzz', $wrong), self::requestClient()),
        );

        self::assertSame('invalid_client', $refused->error);

        DB::table('rate_limits')->delete();

        $this->startMachineRequest();

        $mistaken = $this->assertQueryBudget(
            2,
            2,
            static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange(self::basicClient($public, $wrong), self::requestClient()),
        );

        self::assertSame($refused->toArray(), $mistaken->toArray());
    }

    /**
     * A service account's exchange also reads its membership and the
     * membership's tenant, once each.
     *
     * @return void
     */
    public function testAServiceAccountsExchangeAlsoCostsItsMembershipAndTenant(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('m2m_accounts')->issue($account, $membership);
        $public = $issued->summary->publicId;
        $secret = substr($issued->key()->reveal(), 20);

        $this->startMachineRequest();

        $granted = $this->assertQueryBudget(
            5,
            1,
            static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m_accounts')->exchange(self::basicClient($public, $secret), self::requestClient()),
        );
        $claims = PackageAuth::manager()->jwt('m2m_accounts')->parse((string) $granted->accessToken?->reveal());

        self::assertTrue($granted->isGranted());
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $claims[Claims::TENANT_ID->value] ?? null);
    }

    /**
     * A grant or client authentication method the application does not allow
     * costs no query.
     *
     * @return void
     */
    public function testARefusedGrantOrClientAuthenticationMethodCostsNothing(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys('m2m')->issue($machine, $machine);

        $public = $issued->summary->publicId;
        $secret = substr($issued->key()->reveal(), 20);
        $body   = "grant_type=client_credentials&client_id={$public}&client_secret={$secret}";

        parse_str($body, $parameters);

        $request = Request::create('/oauth/token', 'POST', $parameters, [], [], ['CONTENT_TYPE' => 'application/x-www-form-urlencoded'], $body);

        $this->startMachineRequest();

        $post = $this->assertQueryBudget(
            0,
            0,
            static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange(
                ClientCredentialsRequest::extract($request),
                ClientContext::fromRequest($request),
            ),
        );

        self::assertSame('invalid_client', $post->error);

        config()->set('auth.guards.m2m.application.methods', []);

        $this->startMachineRequest();

        $off = $this->assertQueryBudget(
            0,
            0,
            static fn (): ClientCredentialsResult => PackageAuth::clientCredentials('m2m')->exchange(self::basicClient($public, $secret), self::requestClient()),
        );

        self::assertSame('unauthorized_client', $off->error);
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

        $token = PackageAuth::clientCredentials('m2m')->exchange(
            self::basicClient($issued->summary->publicId, substr($issued->key()->reveal(), 20)),
            self::requestClient(),
        )->accessToken?->reveal();

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
