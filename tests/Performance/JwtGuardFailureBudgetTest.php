<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\Carbon;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity;

/**
 * Query-budget contracts for cheap JwtGuard failure paths.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardFailureBudgetTest extends PerformanceContractTestCase
{
    private const string GUARD = 'api';

    /**
     * Provision the identity table used to mint the expired token fixture.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Release the fixture table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('access_only_identities');

        parent::tearDown();
    }

    /**
     * Malformed bearer tokens should fail before any provider or device query.
     *
     * @return void
     */
    public function testMalformedBearerTokenDoesNotHitTheDatabase(): void
    {
        $this->bindRequestWithBearer('/perf/invalid-bearer', 'not-a-jwt');

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(0, 0, static fn (): bool => $guard->check());

        self::assertFalse($result);
    }

    /**
     * Expired bearer tokens should fail during JWT parse, before any
     * identity/provider hydration.
     *
     * @return void
     */
    public function testExpiredBearerTokenDoesNotHitTheDatabase(): void
    {
        $identity = $this->seedIdentity();

        $token = PackageAuth::jwt(self::GUARD)->issueAccessToken($identity, $identity, null);

        $expiredNow = $this->now->copy()->addMinutes(16);
        Carbon::setTestNow($expiredNow);
        \Firebase\JWT\JWT::$timestamp = $expiredNow->getTimestamp();

        $this->bindRequestWithBearer('/perf/expired-bearer', $token);

        $guard = $this->freshJwtGuard(self::GUARD);

        $result = $this->assertQueryBudget(0, 0, static fn (): bool => $guard->check());

        self::assertFalse($result);
    }

    /**
     * Configure the single access-only JWT guard used by this test.
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

        $config->set('auth.defaults.guard', self::GUARD);

        $config->set('auth.guards.' . self::GUARD, [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => PerformanceAccessOnlyIdentity::class,
        ]);
    }

    /**
     * Persist a single active 2D identity.
     *
     * @return \Tests\Performance\Fixtures\PerformanceAccessOnlyIdentity
     */
    private function seedIdentity(): PerformanceAccessOnlyIdentity
    {
        $hasher = app(Hasher::class);

        $identity = new PerformanceAccessOnlyIdentity;
        $identity->email = 'expired-bearer-performance@example.test';
        $identity->password = $hasher->make('correct horse battery staple');
        $identity->save();

        return $identity;
    }
}
