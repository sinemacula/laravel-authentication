<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;

/**
 * Query-budget contracts for sequential 2D + 3D guard
 * authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardCoexistenceQueryBudgetTest extends PerformanceContractTestCase
{
    private const string GUARD_2D = 'api_2d';
    private const string GUARD_3D = 'api_3d';

    /**
     * Provision the coexistence fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('coexist_2d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the coexistence fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('coexist_3d_principals');
        Schema::dropIfExists('coexist_3d_identities');
        Schema::dropIfExists('coexist_2d_identities');

        parent::tearDown();
    }

    /**
     * A sequential 2D then 3D authentication run should pay one 2D identity
     * read plus the 3D identity + principal reads, with no writes.
     *
     * @return void
     */
    public function testSequentialTwoDimensionalAndThreeDimensionalAuthUsesThreeReadsAndNoWrites(): void
    {
        [$twoDimensionalIdentity, $threeDimensionalIdentity, $threeDimensionalPrincipal] = $this->seedFixtures();

        $twoDimensionalToken = PackageAuth::jwt(self::GUARD_2D)->issueAccessToken(
            $twoDimensionalIdentity,
            $twoDimensionalIdentity,
            null,
        );
        $threeDimensionalToken = PackageAuth::jwt(self::GUARD_3D)->issueAccessToken(
            $threeDimensionalIdentity,
            $threeDimensionalPrincipal,
            null,
        );

        $result = $this->assertQueryBudget(3, 0, function () use (
            $twoDimensionalToken,
            $threeDimensionalToken,
        ): array {
            $this->bindRequestWithBearer('/perf/coexist-2d', $twoDimensionalToken);

            $twoDimensionalGuard         = $this->freshJwtGuard(self::GUARD_2D);
            $twoDimensionalAuthenticated = $twoDimensionalGuard->check();
            $twoDimensionalPrincipalId   = $twoDimensionalGuard->principal()?->getPrincipalIdentifier();

            $this->bindRequestWithBearer('/perf/coexist-3d', $threeDimensionalToken);

            $threeDimensionalGuard         = $this->freshJwtGuard(self::GUARD_3D);
            $threeDimensionalAuthenticated = $threeDimensionalGuard->check();
            $threeDimensionalPrincipalId   = $threeDimensionalGuard->principal()?->getPrincipalIdentifier();

            return [
                'two_dimensional_authenticated'   => $twoDimensionalAuthenticated,
                'two_dimensional_principal'       => $twoDimensionalPrincipalId,
                'three_dimensional_authenticated' => $threeDimensionalAuthenticated,
                'three_dimensional_principal'     => $threeDimensionalPrincipalId,
            ];
        });

        self::assertTrue($result['two_dimensional_authenticated']);
        self::assertSame($twoDimensionalIdentity->getPrincipalIdentifier(), $result['two_dimensional_principal']);
        self::assertTrue($result['three_dimensional_authenticated']);
        self::assertSame($threeDimensionalPrincipal->getPrincipalIdentifier(), $result['three_dimensional_principal']);
    }

    /**
     * Configure the two coexistence guards.
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

        $config->set('auth.defaults.guard', self::GUARD_2D);

        $config->set('auth.guards.' . self::GUARD_2D, [
            'driver'   => 'jwt',
            'provider' => 'coexist_2d_identities',
        ]);

        $config->set('auth.guards.' . self::GUARD_3D, [
            'driver'   => 'jwt',
            'provider' => 'coexist_3d_identities',
        ]);

        $config->set('auth.providers.coexist_2d_identities', [
            'driver' => 'model',
            'model'  => Coexist2dIdentity::class,
        ]);

        $config->set('auth.providers.coexist_3d_identities', [
            'driver' => 'model',
            'model'  => Coexist3dIdentity::class,
        ]);
    }

    /**
     * Persist one 2D identity plus one 3D identity and principal.
     *
     * @return array{0: \Tests\Integration\Fixtures\Coexist2dIdentity, 1:
     *     \Tests\Integration\Fixtures\Coexist3dIdentity, 2: \Tests\Integration\Fixtures\Coexist3dPrincipal}
     */
    private function seedFixtures(): array
    {
        $hasher = app(Hasher::class);

        $twoDimensionalIdentity            = new Coexist2dIdentity;
        $twoDimensionalIdentity->email     = 'coexist-2d-performance@example.test';
        $twoDimensionalIdentity->password  = $hasher->make('correct horse battery staple');
        $twoDimensionalIdentity->is_active = true;
        $twoDimensionalIdentity->save();

        $threeDimensionalIdentity            = new Coexist3dIdentity;
        $threeDimensionalIdentity->email     = 'coexist-3d-performance@example.test';
        $threeDimensionalIdentity->password  = $hasher->make('correct horse battery staple');
        $threeDimensionalIdentity->is_active = true;
        $threeDimensionalIdentity->save();

        $threeDimensionalPrincipal              = new Coexist3dPrincipal;
        $threeDimensionalPrincipal->identity_id = $threeDimensionalIdentity->getKey();
        $threeDimensionalPrincipal->name        = 'coexist-3d-performance-actor';
        $threeDimensionalPrincipal->is_active   = true;
        $threeDimensionalPrincipal->save();

        return [$twoDimensionalIdentity, $threeDimensionalIdentity, $threeDimensionalPrincipal];
    }
}
