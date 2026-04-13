<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubFixedPrincipalResolver;
use Tests\Unit\Stubs\StubPrincipal;
use Tests\Unit\Stubs\StubTenant;

/**
 * Integration tests for guard-local principal resolvers.
 *
 * Verifies that two JWT guards can share one identity model while resolving
 * distinct principals, tenants, and types from guard-specific resolver bindings
 * configured in `auth.guards.<name>.principal_resolver`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(AuthManager::class)]
#[CoversClass(AuthServiceProvider::class)]
final class GuardScopedPrincipalResolverIntegrationTest extends TestCase
{
    /** @var string Guard name for the staff JWT guard. */
    private const string STAFF_GUARD = 'staff';

    /** @var string Guard name for the customer JWT guard. */
    private const string CUSTOMER_GUARD = 'customer';

    /** @var string Container alias for the staff principal resolver. */
    private const string STAFF_RESOLVER = 'staff-principal-resolver';

    /** @var string Container alias for the customer principal resolver. */
    private const string CUSTOMER_RESOLVER = 'customer-principal-resolver';

    /**
     * The same identity can authenticate through two guards that resolve
     * different principals, and a token minted for one guard's resolver is
     * rejected by the other guard's resolver. Rebinding the request clears the
     * previously memoized principal on the old guard instance.
     *
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\Random\RandomException
     */
    public function testGuardsResolveDifferentPrincipalsWithoutCrossContamination(): void
    {
        $identity = $this->seedIdentity();

        $staffTenant       = $this->makeTenant(101, 'staff');
        $customerTenant    = $this->makeTenant(202, 'customer');
        $staffPrincipal    = new PlainPrincipalFixture('staff-actor', $identity, $staffTenant);
        $customerPrincipal = new PlainPrincipalFixture('customer-actor', $identity, $customerTenant);

        $this->bindResolvers($staffPrincipal, $customerPrincipal);

        $staffToken    = PackageAuth::jwt(self::STAFF_GUARD)->issueAccessToken($identity, $staffPrincipal, null);
        $customerToken = PackageAuth::jwt(self::CUSTOMER_GUARD)->issueAccessToken($identity, $customerPrincipal, null);

        $this->bindRequestWithBearer($staffToken);

        $staffGuard = PackageAuth::guard(self::STAFF_GUARD);

        self::assertInstanceOf(ContextualGuard::class, $staffGuard);
        self::assertNotNull($staffGuard->user());
        self::assertSame('staff-actor', $staffGuard->principal()?->getPrincipalIdentifier());
        self::assertSame($staffTenant, $staffGuard->tenant());
        self::assertSame('staff', $staffGuard->type());

        $customerGuard = PackageAuth::guard(self::CUSTOMER_GUARD);

        self::assertInstanceOf(ContextualGuard::class, $customerGuard);
        self::assertFalse($customerGuard->check(), 'Customer guard must reject a token whose pid matches only the staff resolver.');

        $this->bindRequestWithBearer($customerToken);

        self::assertTrue($customerGuard->check());
        self::assertSame('customer-actor', $customerGuard->principal()?->getPrincipalIdentifier());
        self::assertSame($customerTenant, $customerGuard->tenant());
        self::assertSame('customer', $customerGuard->type());

        self::assertNull($staffGuard->identity());
        self::assertNull($staffGuard->principal());
        self::assertNull($staffGuard->tenant());
        self::assertNull($staffGuard->type());
    }

    /**
     * Persist and return an active identity row.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function seedIdentity(): StubPrincipal
    {
        $hasher = app(Hasher::class);

        $identity            = new StubPrincipal;
        $identity->email     = 'guard-local-resolver@example.test';
        $identity->password  = $hasher->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Build an unsaved tenant object with an identifier and type.
     *
     * @param  int  $id
     * @param  string  $type
     * @return \Tests\Unit\Stubs\StubTenant
     */
    private function makeTenant(int $id, string $type): StubTenant
    {
        $tenant = new StubTenant;
        $tenant->forceFill([
            'id'   => $id,
            'type' => $type,
        ]);

        return $tenant;
    }

    /**
     * Register the fixed guard-local resolver bindings used by the test.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $staffPrincipal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $customerPrincipal
     * @return void
     */
    private function bindResolvers(Principal $staffPrincipal, Principal $customerPrincipal): void
    {
        $this->app->instance(self::STAFF_RESOLVER, new StubFixedPrincipalResolver($staffPrincipal));
        $this->app->instance(self::CUSTOMER_RESOLVER, new StubFixedPrincipalResolver($customerPrincipal));
    }

    /**
     * Rebind the current request with the supplied bearer token.
     *
     * @param  string  $token
     * @return void
     */
    private function bindRequestWithBearer(#[\SensitiveParameter] string $token): void
    {
        app()->instance('request', Request::create('/guard-local-resolver', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]));
    }

    /**
     * Switching the default guard flips the package facade's contextual
     * accessors to the guard-local principal, tenant, and type.
     *
     * @return void
     * @throws \Illuminate\Contracts\Container\BindingResolutionException|\Random\RandomException
     */
    public function testDefaultGuardSwitchesFacadeContextBetweenGuardLocalResolvers(): void
    {
        $identity = $this->seedIdentity();

        $staffTenant       = $this->makeTenant(101, 'staff');
        $customerTenant    = $this->makeTenant(202, 'customer');
        $staffPrincipal    = new PlainPrincipalFixture('staff-actor', $identity, $staffTenant);
        $customerPrincipal = new PlainPrincipalFixture('customer-actor', $identity, $customerTenant);

        $this->bindResolvers($staffPrincipal, $customerPrincipal);

        $staffToken    = PackageAuth::jwt(self::STAFF_GUARD)->issueAccessToken($identity, $staffPrincipal, null);
        $customerToken = PackageAuth::jwt(self::CUSTOMER_GUARD)->issueAccessToken($identity, $customerPrincipal, null);

        config()->set('auth.defaults.guard', self::STAFF_GUARD);
        $this->bindRequestWithBearer($staffToken);

        $staffGuard = PackageAuth::guard();

        self::assertInstanceOf(ContextualGuard::class, $staffGuard);
        self::assertTrue($staffGuard->check());
        self::assertSame('staff-actor', PackageAuth::principal()?->getPrincipalIdentifier());
        self::assertSame($staffTenant, PackageAuth::tenant());
        self::assertSame('staff', PackageAuth::type());

        config()->set('auth.defaults.guard', self::CUSTOMER_GUARD);
        $this->bindRequestWithBearer($customerToken);

        $customerGuard = PackageAuth::guard();

        self::assertInstanceOf(ContextualGuard::class, $customerGuard);
        self::assertNotSame($staffGuard, $customerGuard);
        self::assertTrue($customerGuard->check());
        self::assertSame('customer-actor', PackageAuth::principal()?->getPrincipalIdentifier());
        self::assertSame($customerTenant, PackageAuth::tenant());
        self::assertSame('customer', PackageAuth::type());
    }

    /**
     * Provision the in-memory identity table used by both guards.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the in-memory schema.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * Configure two JWT guards that share the same identity provider and use
     * guard-local resolver aliases from the container.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::STAFF_GUARD);

        $config->set('auth.guards.' . self::STAFF_GUARD, [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => self::STAFF_RESOLVER,
        ]);

        $config->set('auth.guards.' . self::CUSTOMER_GUARD, [
            'driver'             => 'jwt',
            'provider'           => 'identities',
            'principal_resolver' => self::CUSTOMER_RESOLVER,
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }
}
