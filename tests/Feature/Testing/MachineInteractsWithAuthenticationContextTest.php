<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\TestCase;

/**
 * Feature tests for the testing helpers on an `api_key` guard: a test acts as a
 * non-human identity, which no credential limits only to none, and a service
 * account's membership with its type and tenant, over requests through
 * `auth:<guard>`; once the test stops acting, the request's own API key
 * authenticates with its scopes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(InteractsWithAuthenticationContext::class)]
final class MachineInteractsWithAuthenticationContextTest extends TestCase
{
    use InteractsWithAuthenticationContext, InteractsWithMachineCredentials;

    /**
     * Create the tables and a route behind each API key guard.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMachineTables();

        foreach (['machine', 'accounts'] as $guard) {
            Route::middleware('auth:' . $guard)->get('/' . $guard . '/me', static fn (): array => [
                'identity'  => Auth::identity()?->getAuthIdentifier(),
                'principal' => Auth::principal()?->getPrincipalIdentifier(),
                'tenant'    => Auth::tenant()?->getTenantIdentifier(),
                'type'      => Auth::type(),
                'scopes'    => Auth::scopes(),
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
     * A machine acted as is limited to no scopes, on every request; once the
     * test stops acting, the request's API key authenticates with its own.
     *
     * @return void
     */
    public function testAMachineActedAsHasNoScopesUntilItsKeyIsPresented(): void
    {
        $robot  = $this->seedMachine();
        $issued = $this->apiKeys()->issue($robot, $robot, ['reports:read']);

        $this->actingAsIdentity($robot, guard: 'machine')->assertBoundScopes([]);

        $this->getJson('/machine/me')->assertOk()->assertJsonPath('identity', $robot->getKey())->assertJsonPath('scopes', []);

        $this->stopActing();

        $this->withToken($issued->key())->getJson('/machine/me')->assertOk()->assertJsonPath('scopes', ['reports:read']);

        $this->assertBoundIdentity($robot)->assertBoundScopes(['reports:read']);
    }

    /**
     * A machine acted as with scopes is limited to them, on every request, as
     * if its key granted them; acting as one of its principals takes them too.
     *
     * @return void
     */
    public function testAMachineActedAsWithScopesIsLimitedToThem(): void
    {
        $robot = $this->seedMachine();

        $this->actingAsIdentity($robot, guard: 'machine', scopes: ['reports:read', 'reports:write'])->assertBoundScopes(['reports:read', 'reports:write']);

        $this->getJson('/machine/me')->assertOk()->assertJsonPath('scopes', ['reports:read', 'reports:write']);
        $this->getJson('/machine/me')->assertOk()->assertJsonPath('scopes', ['reports:read', 'reports:write']);

        [, $membership] = $this->seedAccount();

        $this->actingAsPrincipal($membership, guard: 'accounts', scopes: ['billing:read'])->assertBoundScopes(['billing:read']);

        $this->getJson('/accounts/me')->assertOk()->assertJsonPath('scopes', ['billing:read']);
    }

    /**
     * A service account's membership acted as carries its type and tenant.
     *
     * @return void
     */
    public function testAServiceAccountsMembershipCarriesItsTypeAndTenant(): void
    {
        [$account, $membership, $tenant] = $this->seedAccount();

        $this->actingAsPrincipal($membership, guard: 'accounts')
            ->assertBoundIdentity($account)
            ->assertBoundPrincipal($membership)
            ->assertBoundTenant($tenant)
            ->assertBoundType('service')
            ->assertBoundScopes([]);

        $this->getJson('/accounts/me')->assertOk()->assertExactJson([
            'identity'  => $account->getKey(),
            'principal' => $membership->getKey(),
            'tenant'    => $tenant->getKey(),
            'type'      => 'service',
            'scopes'    => [],
        ]);
    }

    /**
     * Configure the machine guards.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMachineGuards($app->make(ConfigRepository::class));
    }
}
