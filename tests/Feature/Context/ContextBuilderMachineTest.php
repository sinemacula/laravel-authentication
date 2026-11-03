<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\ContextBuilder;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\MachineAccount;
use Tests\Integration\Fixtures\MachineClient;
use Tests\Integration\Fixtures\MachineMembership;
use Tests\TestCase;

/**
 * Feature tests of the authentication context of a machine's request, over HTTP
 * behind `auth`: an API key and a client credentials token each name the
 * machine, the credential's kind and the scopes it grants, with no session and
 * so no proof; a service account's names the membership it acts as and its
 * tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBuilder::class)]
final class ContextBuilderMachineTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /**
     * Create the tables, freeze the clock and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        foreach (['machine', 'accounts', 'm2m'] as $guard) {
            Route::middleware('auth:' . $guard)->get("/{$guard}/context", static fn (): array => ['context' => Auth::context()?->toArray()]);
        }
    }

    /**
     * Drop the tables and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMachineTables();

        self::releaseMachineClock();

        parent::tearDown();
    }

    /**
     * An API key's request is a machine's acting as itself, with the key as the
     * credential and the scopes it grants, and no session, proof or
     * authentication time.
     *
     * @return void
     */
    public function testAnApiKeysContextIsTheMachinesWithItsScopes(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys()->issue($machine, $machine, ['reports:read']);
        $id      = IdentifierCoercion::stringify($machine->getKey());

        self::assertSame([
            'subject_type'          => 'machine',
            'identity_type'         => MachineClient::class,
            'identity_id'           => $id,
            'principal_type'        => MachineClient::class,
            'principal_id'          => $id,
            'tenant_type'           => null,
            'tenant_id'             => null,
            'application'           => 'machine',
            'session_id'            => null,
            'amr'                   => [],
            'auth_time'             => null,
            'mfa'                   => false,
            'recovery_code'         => false,
            'multifactor'           => false,
            'seconds_since_step_up' => null,
            'credential'            => 'api_key',
            'scopes'                => ['reports:read'],
            'ip'                    => self::MACHINE_IP,
        ], $this->contextOf('machine', $issued->key()->reveal())['authentication']);
    }

    /**
     * A client credentials token's request names the machine, the kind of
     * credential and the scopes the token grants, with no session.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientCredentialsTokensContextNamesItsKind(): void
    {
        $machine = $this->seedMachine();
        $issued  = $this->apiKeys('m2m')->issue($machine, $machine, ['read', 'write']);

        $this->startMachineRequest();

        $token = Auth::clientCredentials('m2m')->exchange($issued->summary->publicId, substr($issued->key()->reveal(), 20), 'write')->accessToken;

        self::assertNotNull($token);

        $context = $this->contextOf('m2m', $token->reveal())['authentication'];

        self::assertSame(
            ['machine', 'client_credentials', ['write'], null, [], 'm2m'],
            [$context['subject_type'], $context['credential'], $context['scopes'], $context['session_id'], $context['amr'], $context['application']],
        );
    }

    /**
     * A service account's API key acts as its membership in the membership's
     * tenant.
     *
     * @return void
     */
    public function testAServiceAccountsContextNamesItsMembershipAndTenant(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued  = $this->apiKeys('accounts')->issue($account, $membership);
        $context = $this->contextOf('accounts', $issued->key()->reveal())['authentication'];

        self::assertSame(
            [MachineAccount::class, MachineMembership::class, ActivatableTenant::class, []],
            [$context['identity_type'], $context['principal_type'], $context['tenant_type'], $context['scopes']],
        );
        self::assertSame(
            [IdentifierCoercion::stringify($membership->getKey()), IdentifierCoercion::stringify($tenant->getKey())],
            [$context['principal_id'], $context['tenant_id']],
        );
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

    /**
     * The context the guard's route answers for the bearer credential.
     *
     * @param  string  $guard
     * @param  string  $credential
     * @return array<string, array<string, mixed>>
     */
    private function contextOf(string $guard, #[\SensitiveParameter] string $credential): array
    {
        Auth::forgetGuards();

        /** @var array<string, array<string, mixed>> */
        return $this->withServerVariables(['REMOTE_ADDR' => self::MACHINE_IP])->withToken($credential)->getJson("/{$guard}/context")->assertOk()->json('context');
    }
}
