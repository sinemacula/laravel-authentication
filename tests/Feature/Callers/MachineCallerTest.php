<?php

declare(strict_types = 1);

namespace Tests\Feature\Callers;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\CallerCredentials;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\MachineMembership;
use Tests\TestCase;

/**
 * Feature tests for the principals a machine's caller owns.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerCredentials::class)]
#[CoversClass(Caller::class)]
final class MachineCallerTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /**
     * Create the tables and register a route per guard that answers what the
     * caller owns.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        foreach (['accounts', 'm2m_accounts'] as $guard) {
            Route::middleware('auth:' . $guard)->get("/{$guard}/owns/{own}/{sibling}", static fn (string $own, string $sibling): array => [
                'own'     => Auth::caller()?->owns(MachineMembership::query()->whereKey($own)->firstOrFail()),
                'sibling' => Auth::caller()?->owns(MachineMembership::query()->whereKey($sibling)->firstOrFail()),
            ]);
        }
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
     * An API key's caller and a client credentials token's caller own only the
     * principal the key is bound to, not another the machine may use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAMachinesCallerOwnsOnlyItsKeysPrincipal(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $sibling = MachineMembership::query()->create([
            'account_id'  => $account->getKey(),
            'tenant_type' => $tenant->getMorphClass(),
            'tenant_id'   => $tenant->getKey(),
            'type'        => 'service',
        ]);

        $path = IdentifierCoercion::stringify($membership->getKey()) . '/' . IdentifierCoercion::stringify($sibling->getKey());

        $this->startMachineRequest();

        $key    = $this->apiKeys('accounts')->issue($account, $membership)->key()->reveal();
        $issued = $this->apiKeys('m2m_accounts')->issue($account, $membership);
        $result = Auth::clientCredentials('m2m_accounts')->exchange(self::basicClient($issued->summary->publicId, substr($issued->key()->reveal(), 20)), self::requestClient());

        self::assertNotNull($result->accessToken);

        foreach (['accounts' => $key, 'm2m_accounts' => $result->accessToken->reveal()] as $guard => $token) {

            Auth::forgetGuards();

            $this->withToken($token)->getJson("/{$guard}/owns/{$path}")->assertOk()->assertExactJson(['own' => true, 'sibling' => false]);
        }
    }

    /**
     * Register the machine guards.
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
