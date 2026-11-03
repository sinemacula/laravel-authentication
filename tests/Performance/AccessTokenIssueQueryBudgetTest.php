<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithTypedPrincipals;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;

/**
 * Query-budget contracts for issuing an access token: issuing reads nothing,
 * not even the tenant a 3D principal acts within, unless the token names that
 * tenant and the principal has not loaded it, and the bearer request the token
 * then authenticates pays only its own reads. A token for a session costs the
 * one `UPDATE` of the session's issuance guard, which comes first so the token
 * reads the session's proofs after any issuance or proof change of it that
 * overlaps, and the one grouped read of those proofs for its `auth_time` and
 * `amr`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
final class AccessTokenIssueQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithProofs, InteractsWithSessionRecords, InteractsWithTypedPrincipals;

    /** @var string Guard the budgets are measured on. */
    private const string GUARD = 'typed_api';

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createTypedPrincipalTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropTypedPrincipalTables();

        parent::tearDown();
    }

    /**
     * Issuing an access token for a 3D principal whose tenant is not loaded
     * runs no query and leaves the tenant unloaded.
     *
     * @return void
     */
    public function testIssuingForAPrincipalInATenantReadsNothing(): void
    {
        [$identity, $membership] = $this->seedMembership();

        $token = $this->assertQueryBudget(0, 0, fn (): string => $this->tokens()->issueAccessToken($identity, $membership, null, null)->reveal());

        self::assertNotSame('', $token);
        self::assertFalse($membership->relationLoaded('tenant'));
    }

    /**
     * Issuing a token that names the principal's tenant checks it is the
     * principal's own: through the relation the caller loaded the tenant with,
     * at no read, or, with that relation unloaded, at the one read that loads
     * it, and never a write.
     *
     * @return void
     */
    public function testIssuingWithTheTenantReadsItAtMostOnce(): void
    {
        [$identity, $membership] = $this->seedMembership();

        $tenant = $membership->getTenant();

        self::assertNotNull($tenant);
        self::assertNotSame('', $this->assertQueryBudget(0, 0, fn (): string => $this->tokens()->issueAccessToken($identity, $membership, $tenant, null)->reveal()));

        $membership->unsetRelation('tenant');

        self::assertNotSame('', $this->assertQueryBudget(1, 0, fn (): string => $this->tokens()->issueAccessToken($identity, $membership, $tenant, null)->reveal()));
        self::assertTrue($membership->relationLoaded('tenant'));
    }

    /**
     * Issuing a token for a stored session writes its issuance guard and reads
     * its proofs once, however many it holds.
     *
     * @return void
     */
    public function testIssuingForASessionWritesItsGuardAndReadsItsProofsOnce(): void
    {
        [$identity, $membership] = $this->seedMembership();

        $session = new Session;

        $session->forceFill([
            ...self::liveSession(self::GUARD),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()),
        ])->save();

        foreach (range(0, 9) as $minutes) {
            $kind = $minutes === 0 ? ProofKind::FIRST_FACTOR : ProofKind::ADDITIONAL_FACTOR;

            self::recordProof($session, $kind, Carbon::now()->subMinutes(10 - $minutes), ['pwd'], new Evaluation(true, true));
        }

        self::assertNotSame('', $this->assertQueryBudget(1, 1, fn (): string => $this->tokens()->issueAccessToken($identity, $membership, null, $session)->reveal()));
    }

    /**
     * The bearer request for that token authenticates in its own reads, the
     * identity, the principal and the tenant the activity check loads, and
     * writes nothing: the read the token's issue skipped is not moved to it.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testTheIssuedTokenAuthenticatesInThreeReads(): void
    {
        [$identity, $membership] = $this->seedMembership();

        $this->bindRequestWithBearer('/perf/typed', $this->tokens()->issueAccessToken($identity, $membership, null, null)->reveal());

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertTrue($this->assertQueryBudget(3, 0, static fn (): bool => $guard->check()));
        self::assertSame($membership->getKey(), $guard->principal()?->getPrincipalIdentifier());
    }

    /**
     * Configure the guard.
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
     * Persist an identity and one membership of a tenant, returned without its
     * tenant loaded.
     *
     * @return array{0: \Tests\Integration\Fixtures\TypedIdentity, 1: \Tests\Integration\Fixtures\TypedMembership}
     */
    private function seedMembership(): array
    {
        $identity   = TypedIdentity::query()->create(['email' => 'typed@example.test', 'password' => 'unused']);
        $tenant     = TypedTenant::query()->create(['category' => 'staff']);
        $membership = TypedMembership::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey(), 'type' => 'client_admin']);

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
