<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\StubMutablePrincipalResolver;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * A refresh that fails while issuing the new token pair leaves the presented
 * refresh token valid, on the suite's configured database.
 *
 * Both tokens are issued before the rotation commits, so a failure while
 * issuing cannot consume the stored digest and sign the device out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(JwtGuard::class)]
final class JwtGuardRefreshIssuingFailureIntegrationTest extends TestCase
{
    /** @var string Plaintext rotation id stored on the seeded device. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        parent::tearDown();
    }

    /**
     * The resolver hands back a principal that was never saved, so the token
     * service refuses to issue the access token: the refresh throws, the stored
     * digest is unchanged in the database, and the same refresh token rotates
     * once the resolver returns a saved principal.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshTokenStaysValidWhenIssuingTheNewPairFails(): void
    {
        $identity = new StubPrincipal;
        $identity->forceFill(['email' => 'issuing@example.test', 'password' => 'irrelevant'])->save();

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID);

        $resolver = new StubMutablePrincipalResolver;
        $resolver->setDefaultPrincipal(new StubPrincipal);

        try {
            $this->guard($resolver)->refresh($refreshToken);

            self::fail('The issuing failure should have propagated.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('without its `pid` claim', $exception->getMessage());
        }

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->storedDigest($device));

        $resolver->setDefaultPrincipal($identity);

        $guard = $this->guard($resolver);

        self::assertInstanceOf(RefreshResult::class, $guard->refresh($refreshToken));
        self::assertTrue($identity->is($guard->user()));
        self::assertNotSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->storedDigest($device));
    }

    /**
     * Configure the `api` guard against the stub identity provider.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Read the device's stored refresh digest from the database.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Device  $device
     * @return ?string
     */
    private function storedDigest(Device $device): ?string
    {
        $fresh = Device::query()->findOrFail($device->getKey());

        assert($fresh instanceof Device);

        return $fresh->getRefreshKey();
    }

    /**
     * Resolve a fresh `api` guard for a new request, bound to the resolver.
     *
     * @param  \Tests\Unit\Stubs\StubMutablePrincipalResolver  $resolver
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(StubMutablePrincipalResolver $resolver): JwtGuard
    {
        app()->instance('request', Request::create('/refresh', 'POST'));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        $guard->setPrincipalResolver($resolver);

        return $guard;
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }
}
