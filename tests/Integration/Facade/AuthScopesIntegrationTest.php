<?php

declare(strict_types = 1);

namespace Tests\Integration\Facade;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * `Auth::scopes()` through the facade: a human identity's session carries no
 * scope ceiling, a machine identity bound without a credential is limited to no
 * scope, and a guard that is not the package's has none to report.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthManager::class)]
final class AuthScopesIntegrationTest extends TestCase
{
    use InteractsWithMachineClients, InteractsWithSessions;

    /**
     * Create the identity and machine tables and a route reporting the scopes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        self::createMachineClientsTable();

        Route::middleware('auth:api')->get('/scopes', static fn (): array => ['scopes' => Auth::scopes()]);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropMachineClientsTable();

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * A request with a human identity's session token has no scope ceiling.
     *
     * @return void
     */
    public function testAHumanSessionHasNoScopeCeiling(): void
    {
        $this->seedIdentity();

        $result = $this->sessions()->signIn('password', self::credentials(), SignInContext::fromRequest(request()));

        self::assertNotNull($result->session);

        $this->withToken($result->session->tokens->accessToken)
            ->getJson('/scopes')
            ->assertOk()
            ->assertExactJson(['scopes' => null]);
    }

    /**
     * A machine identity bound through Laravel's `actingAs()` or the trusted
     * `login()` is limited to no scope, and its context event says so.
     *
     * @return void
     */
    public function testAMachineBoundWithoutACredentialIsLimitedToNoScope(): void
    {
        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);

        $this->actingAs($machine, 'api');

        self::assertSame([], Auth::scopes());

        $this->recordEvents([PrincipalAssigned::class]);

        Auth::forgetGuards();
        Auth::shouldUse('api');
        Auth::guard('api')->login($machine, $machine);

        self::assertSame([], Auth::scopes());
        self::assertSame([], $this->recordedEvent(PrincipalAssigned::class)->context()->scopes);
    }

    /**
     * A default guard that is not contextual reports no scopes.
     *
     * @return void
     */
    public function testANonContextualGuardReportsNoScopes(): void
    {
        config()->set('auth.guards.web', ['driver' => 'session', 'provider' => 'identities']);

        Auth::shouldUse('web');

        self::assertNull(Auth::scopes());
    }

    /**
     * Configure the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }
}
