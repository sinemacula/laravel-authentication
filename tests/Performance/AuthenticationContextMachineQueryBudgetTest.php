<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContextBuilder;
use SineMacula\Laravel\Authentication\Facades\Auth;
use Tests\Concerns\InteractsWithMachineCredentials;

/**
 * Query-budget contracts for the authentication context of a machine's request:
 * an API key and a client credentials token have no session, so once the guard
 * has authenticated the request their context reads nothing at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBuilder::class)]
final class AuthenticationContextMachineQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithMachineCredentials;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();
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
     * An API key's context costs no query once the key is authenticated.
     *
     * @return void
     */
    public function testAnApiKeysContextReadsNothing(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['reports:read']);

        $this->startMachineRequest($issued->key()->reveal());

        Auth::shouldUse('machine');

        self::assertTrue(Auth::guard('machine')->check());

        $context = $this->assertQueryBudget(0, 0, static fn (): ?AuthenticationContext => Auth::context());

        self::assertSame('api_key', $context?->credential?->value);
    }

    /**
     * A client credentials token's context costs no query once the token is
     * authenticated.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientCredentialsTokensContextReadsNothing(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys('m2m')->issue($machine, $machine);

        $this->startMachineRequest();

        $token = Auth::clientCredentials('m2m')->exchange(self::basicClient($issued->summary->publicId, substr($issued->key()->reveal(), 20)), self::requestClient())->accessToken;

        self::assertNotNull($token);

        $this->startMachineRequest($token->reveal());

        Auth::shouldUse('m2m');

        self::assertTrue(Auth::guard('m2m')->check());

        $context = $this->assertQueryBudget(0, 0, static fn (): ?AuthenticationContext => Auth::context());

        self::assertSame('client_credentials', $context?->credential?->value);
    }

    /**
     * Register the guards and providers.
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
