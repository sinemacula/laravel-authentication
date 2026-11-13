<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\AuthenticatedBearer;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineAccount;
use Tests\Integration\Fixtures\MachineClient;
use Tests\Integration\Fixtures\MachineMembership;
use Tests\TestCase;

/**
 * Feature tests for client credentials access tokens on the `jwt` guard's
 * bearer path, each held to its API key on every request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
#[CoversClass(AuthenticatedBearer::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(ApiKeyLookup::class)]
final class ClientTokenBearerAuthenticationTest extends TestCase
{
    use InteractsWithMachineCredentials;

    /**
     * Create the tables, freeze the clock, register the routes and record the
     * events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        foreach (['m2m', 'm2m_accounts', 'api'] as $guard) {
            Route::middleware('auth:' . $guard)->get("/{$guard}/me", static fn (): array => [
                'identity' => Auth::guard($guard)->id(),
                'scopes'   => Auth::manager()->guard($guard) instanceof JwtGuard ? Auth::manager()->guard($guard)->scopes() : null,
                'session'  => Auth::manager()->guard($guard) instanceof JwtGuard ? Auth::manager()->guard($guard)->session() : null,
            ]);
        }

        $this->recordMachineEvents([AuthenticationFailed::class, Authenticated::class, PrincipalAssigned::class, Validated::class, Login::class]);
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
     * A client token binds its machine with its scopes and no session,
     * reporting `client_credentials`, its key and scopes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientTokenBindsItsMachineWithItsScopes(): void
    {
        [$machine, $issued] = $this->machineKey(['read', 'write']);

        $token = $this->exchange($issued, 'write');

        $this->machineEvents = [];

        $this->bearer('/m2m/me', $token)->assertOk()->assertExactJson(['identity' => $machine->getKey(), 'scopes' => ['write'], 'session' => null]);

        self::assertSame([Authenticated::class, PrincipalAssigned::class], $this->machineEventClasses());

        $context = $this->machineEventsOf(PrincipalAssigned::class)[0]->context;

        self::assertSame('client_credentials', $context->method);
        self::assertSame($issued->id, $context->credentialId);
        self::assertSame(['write'], $context->scopes);
    }

    /**
     * The bound caller of a client token names its key by its id, which is no
     * part of the token or the key.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheBoundCallerNamesTheTokensKeyByItsId(): void
    {
        [, $issued] = $this->machineKey(['read']);

        $token = $this->exchange($issued);

        $this->startMachineRequest($token);

        $guard = Auth::manager()->guard('m2m');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->user();

        $caller = $guard->boundCaller();

        self::assertNotNull($caller);
        self::assertSame(CredentialKind::CLIENT_CREDENTIALS, $caller->credentialKind);
        self::assertSame($issued->id, $caller->credentialId);
        self::assertStringNotContainsString($issued->id, $issued->key()->reveal());
    }

    /**
     * A key with the longest list of scopes is exchanged for a token that
     * grants every one of them, in order.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenForTheLongestListOfScopesCarriesItWhole(): void
    {
        $scopes = self::longestScopes();

        [, $issued] = $this->machineKey($scopes);

        $token = $this->exchange($issued);

        self::assertGreaterThan(8192, strlen('Authorization: Bearer ' . $token));

        $this->bearer('/m2m/me', $token)->assertOk()->assertJsonPath('scopes', $scopes);
    }

    /**
     * Revoking the key rejects its live token at the next request.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRevokingTheKeyEndsItsTokensAtOnce(): void
    {
        [$machine, $issued] = $this->machineKey(['read']);

        $token = $this->exchange($issued);

        $this->bearer('/m2m/me', $token)->assertOk();

        $this->apiKeys('m2m')->revoke($machine, $issued->id);

        $this->assertRefused('/m2m/me', $token, FailureReason::CREDENTIAL_REVOKED, $issued->id, ['read']);
    }

    /**
     * A token of a rotated key works through the overlap and is rejected once
     * it ends, as `credential_expired`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARotatedKeysTokensEndWithItsOverlap(): void
    {
        [$machine, $issued] = $this->machineKey();

        $token = $this->exchange($issued);

        $this->apiKeys('m2m')->rotate($machine, $issued->id, 60);

        self::travelMachineClock(59);

        $this->bearer('/m2m/me', $token)->assertOk();

        self::travelMachineClock(1);

        $this->assertRefused('/m2m/me', $token, FailureReason::CREDENTIAL_EXPIRED, $issued->id, []);
    }

    /**
     * A token whose key is gone, or is now another guard's, is
     * `credential_invalid`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenWhoseKeyIsGoneOrMovedIsInvalid(): void
    {
        [, $issued] = $this->machineKey();

        $token = $this->exchange($issued);

        DB::table('api_keys')->update(['guard' => 'machine']);

        $this->assertRefused('/m2m/me', $token, FailureReason::CREDENTIAL_INVALID, $issued->id, []);

        DB::table('api_keys')->delete();

        $this->assertRefused('/m2m/me', $token, FailureReason::CREDENTIAL_INVALID, $issued->id, []);

        self::assertNull(ApiKeyLookup::findById('not-a-uuid'));
    }

    /**
     * A token whose subject the provider now returns as a human identity is
     * `credential_invalid`: client tokens are a machine's only.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenWhoseSubjectIsHumanIsInvalid(): void
    {
        [$machine, $issued] = $this->machineKey();

        $token = $this->exchange($issued);

        IntegrationIdentity::query()->create(['id' => $machine->getKey(), 'email' => 'ada@example.test']);

        config()->set('auth.providers.machines.model', IntegrationIdentity::class);

        $this->assertRefused('/m2m/me', $token, FailureReason::CREDENTIAL_INVALID, $issued->id, []);
    }

    /**
     * A token whose key records a human owner is `credential_invalid` though
     * the binding holds.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenOfAKeyRecordingAHumanIsInvalid(): void
    {
        [$machine, $issued] = $this->machineKey();

        $token = $this->exchange($issued);

        IntegrationIdentity::query()->create(['id' => $machine->getKey(), 'email' => 'ada@example.test']);

        config()->set('auth.providers.machines.model', IntegrationIdentity::class);
        DB::table('api_keys')->update(['authenticatable_type' => IntegrationIdentity::class, 'principal_type' => IntegrationIdentity::class]);

        $this->assertRefused('/m2m/me', $token, FailureReason::CREDENTIAL_INVALID, $issued->id, []);
    }

    /**
     * A token's machine must still be active.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokensMachineMustStillBeActive(): void
    {
        [$machine, $issued] = $this->machineKey();

        $token = $this->exchange($issued);

        $machine->forceFill(['is_active' => false])->save();

        $this->assertRefused('/m2m/me', $token, FailureReason::IDENTITY_INACTIVE, $issued->id, []);
    }

    /**
     * A token is rejected once the principal, tenant or owner its key records
     * changes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenStaysBoundToItsKeysPrincipalTenantAndOwner(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('m2m_accounts')->issue($account, $membership, ['read']);
        $token  = $this->exchange($issued, null, 'm2m_accounts');

        $this->bearer('/m2m_accounts/me', $token)->assertOk();

        $other = $tenant->replicate();
        $other->save();
        $membership->forceFill(['tenant_id' => $other->getKey()])->save();

        $this->assertRefused('/m2m_accounts/me', $token, FailureReason::PRINCIPAL_MISMATCH, $issued->id, ['read']);

        $membership->forceFill(['tenant_id' => $tenant->getKey()])->save();
        DB::table('api_keys')->update(['principal_type' => MachineClient::class]);

        $this->assertRefused('/m2m_accounts/me', $token, FailureReason::PRINCIPAL_MISMATCH, $issued->id, ['read']);

        DB::table('api_keys')->update(['principal_type' => (new MachineMembership)->getMorphClass(), 'authenticatable_type' => MachineClient::class]);

        $this->assertRefused('/m2m_accounts/me', $token, FailureReason::CREDENTIAL_INVALID, $issued->id, ['read']);

        DB::table('api_keys')->update(['authenticatable_type' => MachineAccount::class]);

        $this->bearer('/m2m_accounts/me', $token)->assertOk();
    }

    /**
     * A token is rejected as `principal_mismatch` while its membership sits in
     * a tenant of another type under the same identifier.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenStaysBoundToItsKeysTenantType(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $issued = $this->apiKeys('m2m_accounts')->issue($account, $membership, ['read']);
        $token  = $this->exchange($issued, null, 'm2m_accounts');

        $this->moveToAWorkspaceOfTheSameId($membership, $tenant);

        $this->assertRefused('/m2m_accounts/me', $token, FailureReason::PRINCIPAL_MISMATCH, $issued->id, ['read']);

        $membership->forceFill(['tenant_type' => $tenant->getMorphClass()])->save();

        $this->bearer('/m2m_accounts/me', $token)->assertOk();
    }

    /**
     * A client token is its guard's only: another guard rejects it as
     * `token_invalid`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClientTokenIsItsGuardsOnly(): void
    {
        [, $issued] = $this->machineKey();

        $token = $this->exchange($issued);

        $this->machineEvents = [];

        $this->bearer('/api/me', $token)->assertUnauthorized();

        self::assertSame(FailureReason::TOKEN_INVALID, $this->machineEventsOf(AuthenticationFailed::class)[0]->reason);
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

    /**
     * A machine and a key of the `m2m` guard granting the scopes.
     *
     * @param  list<string>  $scopes
     * @return array{0: \Tests\Integration\Fixtures\MachineClient, 1: \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey}
     */
    private function machineKey(array $scopes = []): array
    {
        $machine = $this->seedMachine();

        return [$machine, $this->apiKeys('m2m')->issue($machine, $machine, $scopes)];
    }

    /**
     * Exchange the key for an access token of the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\ApiKeys\IssuedApiKey  $issued
     * @param  ?string  $scope
     * @param  string  $guard
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function exchange(IssuedApiKey $issued, ?string $scope = null, string $guard = 'm2m'): string
    {
        $this->startMachineRequest();

        $result = Auth::clientCredentials($guard)->exchange(self::basicClient($issued->summary->publicId, substr($issued->key()->reveal(), 20), $scope), self::requestClient());

        self::assertNotNull($result->accessToken);

        Auth::forgetGuards();

        return $result->accessToken->reveal();
    }

    /**
     * Request the path with the token.
     *
     * @param  string  $path
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $path, #[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withToken($token)->getJson($path);
    }

    /**
     * Assert the token is refused on the path with the reason, reported once on
     * the bearer flow with the key, its scopes and `client_credentials`.
     *
     * @param  string  $path
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  string  $credentialId
     * @param  list<string>  $scopes
     * @return void
     */
    private function assertRefused(string $path, #[\SensitiveParameter] string $token, FailureReason $reason, string $credentialId, array $scopes): void
    {
        $this->machineEvents = [];

        $this->bearer($path, $token)->assertUnauthorized();

        $failures = $this->machineEventsOf(AuthenticationFailed::class);

        self::assertCount(1, $failures);
        self::assertSame($reason, $failures[0]->reason);
        self::assertSame(AuthenticationFlow::BEARER, $failures[0]->flow);
        self::assertSame($credentialId, $failures[0]->context->credentialId);
        self::assertSame($scopes, $failures[0]->context->scopes);
        self::assertSame('client_credentials', $failures[0]->context->method);
    }
}
