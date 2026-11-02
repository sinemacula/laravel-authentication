<?php

declare(strict_types = 1);

namespace Tests\Feature\Routing;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Routing\MeBinding;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Integration\Fixtures\MeMachine;
use Tests\TestCase;

/**
 * Feature tests of the `me` route binding behind an API key guard, driven over
 * HTTP: `me` binds the machine identity the key authenticates, its own id binds
 * it too, and another machine's id is a `404`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MeBinding::class)]
final class ApiKeyMeBindingTest extends TestCase
{
    use InteractsWithMachineClients;

    /**
     * Create the machine table and register the route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createMachineClientsTable();

        Route::pattern('machine', '[0-9]+|me');

        Route::middleware(['auth:machine', SubstituteBindings::class])->get('/machines/{machine}', static fn (MeMachine $machine): array => ['id' => $machine->getKey()]);
    }

    /**
     * Drop the machine table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropMachineClientsTable();

        parent::tearDown();
    }

    /**
     * The key's machine is `me` and its own id; another machine is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMeIsTheMachineTheKeyAuthenticates(): void
    {
        $machine = MeMachine::query()->create(['email' => 'robot@example.test']);
        $other   = MeMachine::query()->create(['email' => 'other@example.test']);

        app()->instance('request', Request::create('/machine'));

        Auth::forgetGuards();

        $key = Auth::apiKeys('machine')->issue($machine, $machine)->key()->reveal();

        $this->withKey('/machines/me', $key)->assertOk()->assertExactJson(['id' => $machine->getKey()]);
        $this->withKey('/machines/' . IdentifierCoercion::stringify($machine->getKey()), $key)->assertOk()->assertExactJson(['id' => $machine->getKey()]);
        $this->withKey('/machines/' . IdentifierCoercion::stringify($other->getKey()), $key)->assertNotFound();
    }

    /**
     * Register the API key guard over the machines.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        $config->set('auth.providers.machines', ['driver' => 'model', 'model' => MeMachine::class]);
        $config->set('auth.guards.machine', ['driver' => 'api_key', 'provider' => 'machines', 'application' => ['methods' => ['api_key']]]);
    }

    /**
     * Get the route with the API key, on guards resolved afresh.
     *
     * @param  string  $uri
     * @param  string  $key
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function withKey(string $uri, #[\SensitiveParameter] string $key): TestResponse
    {
        Auth::forgetGuards();

        return $this->getJson($uri, ['Authorization' => 'Bearer ' . $key]);
    }
}
