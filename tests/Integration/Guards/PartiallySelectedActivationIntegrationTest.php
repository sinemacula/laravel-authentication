<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Concerns\ProvidesActiveState;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\PartiallySelectedIdentity;
use Tests\TestCase;

/**
 * An identity that opts into activation but is loaded without its activation
 * column fails every authentication path loudly instead of reading the missing
 * flag as active or inactive, so a partial select surfaces as a
 * misconfiguration rather than silently changing who can sign in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationPolicy::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversTrait(ProvidesActiveState::class)]
final class PartiallySelectedActivationIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Plaintext rotation id stored on the seeded device. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var string Message of the misconfiguration report. */
    private const string NOT_LOADED = 'its `is_active` attribute is not loaded';

    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('partially_selected_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
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
        Schema::dropIfExists('partially_selected_identities');

        parent::tearDown();
    }

    /**
     * Signing in reports the unloaded flag instead of signing in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptReportsAnIdentityLoadedWithoutItsActiveFlag(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->guardForRequest(Request::create('/sign-in', 'POST'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::NOT_LOADED);

        $guard->attempt(['email' => $identity->email, 'password' => self::PASSWORD]);
    }

    /**
     * A bearer request answers with a server error carrying the report, not
     * with the identity or a 401.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerAnswersAnIdentityLoadedWithoutItsActiveFlagWithAServerError(): void
    {
        $identity = $this->seedIdentity();
        $token    = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null);

        Route::middleware('auth:api')->get('/me', static fn (): string => 'ok');

        $response = $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');

        $response->assertInternalServerError();

        self::assertInstanceOf(\LogicException::class, $response->exception);
        self::assertStringContainsString(self::NOT_LOADED, $response->exception->getMessage());
    }

    /**
     * Refreshing reports the unloaded flag, and the stored rotation is left
     * untouched.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshReportsAnIdentityLoadedWithoutItsActiveFlag(): void
    {
        $identity = $this->seedIdentity();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => PartiallySelectedIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID, $identity);
        $guard        = $this->guardForRequest(Request::create('/refresh', 'POST'));

        try {
            $guard->refresh($refreshToken);

            self::fail('The unloaded activation flag should have been reported.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString(self::NOT_LOADED, $exception->getMessage());
        }

        $fresh = Device::query()->findOrFail($device->getKey());

        assert($fresh instanceof Device);

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $fresh->getRefreshKey());
    }

    /**
     * Configure the `api` guard against the partially selected identity.
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

        $config->set('auth.defaults.guard', 'api');

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'partially_selected',
        ]);

        $config->set('auth.providers.partially_selected', [
            'driver' => 'model',
            'model'  => PartiallySelectedIdentity::class,
        ]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an active identity with a hashed password.
     *
     * @return \Tests\Integration\Fixtures\PartiallySelectedIdentity
     */
    private function seedIdentity(): PartiallySelectedIdentity
    {
        $identity = new PartiallySelectedIdentity;
        $identity->forceFill([
            'email'     => 'partial@example.test',
            'password'  => app(Hasher::class)->make(self::PASSWORD),
            'is_active' => true,
        ])->save();

        return $identity;
    }

    /**
     * Resolve a fresh `api` JWT guard bound to the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

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
