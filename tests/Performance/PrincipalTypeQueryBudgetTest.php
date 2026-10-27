<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\PrincipalType;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;

/**
 * Query-budget contracts for reading a principal's type: a principal with a
 * type of its own never loads its tenant, and one without loads it once.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalType::class)]
#[CoversClass(JwtTokenService::class)]
final class PrincipalTypeQueryBudgetTest extends PerformanceContractTestCase
{
    /** @var string Guard the budgets are measured on. */
    private const string GUARD = 'typed_api';

    /**
     * Create the typed tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('typed_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('typed_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('category')->nullable();
            $blueprint->timestamps();
        });

        Schema::create('typed_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id')->nullable();
            $blueprint->string('type')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the typed tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('typed_memberships');
        Schema::dropIfExists('typed_tenants');
        Schema::dropIfExists('typed_identities');

        parent::tearDown();
    }

    /**
     * Issuing an access token for a principal with a type of its own adds no
     * query, even though its tenant is not loaded.
     *
     * @return void
     */
    public function testIssuingForATypedPrincipalReadsNothing(): void
    {
        [$identity, $membership] = $this->seedMembership('client_admin');

        $token = $this->assertQueryBudget(0, 0, fn (): string => $this->tokens()->issueAccessToken($identity, $membership, null));

        self::assertNotSame('', $token);
        self::assertFalse($membership->relationLoaded('tenant'));
    }

    /**
     * Issuing for a principal without a type reads its tenant once, and the
     * loaded tenant then serves `type()` again without a query.
     *
     * @return void
     */
    public function testIssuingForAnUntypedPrincipalReadsItsTenantOnce(): void
    {
        [$identity, $membership] = $this->seedMembership(null);

        $this->assertQueryBudget(1, 0, fn (): string => $this->tokens()->issueAccessToken($identity, $membership, null));

        self::assertSame('staff', $this->assertQueryBudget(0, 0, static fn (): ?string => PrincipalType::of($membership)));
    }

    /**
     * On a bearer request for a principal with a type of its own, `type()` adds
     * no query to the authentication's reads.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testTypeOfATypedPrincipalAddsNoQueryToTheBearerPath(): void
    {
        [$identity, $membership] = $this->seedMembership('client_admin', false);

        $this->bindRequestWithBearer('/perf/typed', $this->tokens()->issueAccessToken($identity, $membership, null));

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertTrue($this->assertQueryBudget(2, 0, static fn (): bool => $guard->check()));
        self::assertSame('client_admin', $this->assertQueryBudget(0, 0, static fn (): ?string => $guard->type()));
    }

    /**
     * Configure the typed guard.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'typed']);
        $config->set('auth.providers.typed', ['driver' => 'model', 'model' => TypedIdentity::class]);
    }

    /**
     * Persist an identity and one membership of the given type, in a `staff`
     * tenant unless told otherwise, returned without its tenant loaded.
     *
     * @param  ?string  $type
     * @param  bool  $inTenant
     * @return array{0: \Tests\Integration\Fixtures\TypedIdentity, 1: \Tests\Integration\Fixtures\TypedMembership}
     */
    private function seedMembership(?string $type, bool $inTenant = true): array
    {
        $identity = TypedIdentity::query()->create(['email' => 'typed@example.test', 'password' => 'unused']);
        $tenant   = $inTenant ? TypedTenant::query()->create(['category' => 'staff']) : null;

        $membership = TypedMembership::query()->create([
            'identity_id' => $identity->getKey(),
            'tenant_id'   => $tenant?->getKey(),
            'type'        => $type,
        ]);

        $membership->setRelation('identity', $identity);

        return [$identity, $membership];
    }

    /**
     * The guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        return PackageAuth::manager()->jwt(self::GUARD);
    }
}
