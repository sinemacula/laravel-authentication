<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\UnresolvableIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * An identity model that is neither a `Principal` nor `HasPrincipals` is a
 * misconfiguration. It surfaces as a server error on the credential, bearer,
 * and refresh paths instead of being reported as a failed authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class MisconfiguredIdentityIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string */
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

        Schema::create('unresolvable_identities', static function (Blueprint $blueprint): void {
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
        Schema::dropIfExists('unresolvable_identities');

        parent::tearDown();
    }

    /**
     * A credential attempt with the correct password throws instead of
     * returning `false`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptThrowsForIdentityThatCannotResolveAPrincipal(): void
    {
        $identity = $this->seedIdentity();

        $this->expectException(UnresolvableIdentityException::class);

        $this->freshGuard()->attempt(['email' => $identity->email, 'password' => self::PASSWORD]);
    }

    /**
     * A bearer request answers with a server error, not 401.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRequestAnswersWithServerError(): void
    {
        $identity = $this->seedIdentity();
        $token    = $this->authManager()->jwt('api')->issueAccessToken($identity, new PlainPrincipalFixture(7), null);

        Route::middleware('auth:api')->get('/me', static fn (): string => 'ok');

        $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me')
            ->assertInternalServerError();
    }

    /**
     * Refresh throws without reporting a refresh failure.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshThrowsWithoutReportingARefreshFailure(): void
    {
        $identity = $this->seedIdentity();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => UnresolvableIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->authManager()->jwt('api')->issueRefreshToken($device, self::ROTATION_ID);

        Event::fake([AuthenticationFailed::class]);

        try {
            $this->freshGuard()->refresh($refreshToken);
            self::fail('Expected the UnresolvableIdentityException to propagate.');
        } catch (UnresolvableIdentityException) {
            Event::assertNotDispatched(AuthenticationFailed::class);
        }
    }

    /**
     * Configure the JWT guard against the misconfigured identity provider.
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
            'provider' => 'unresolvable',
        ]);

        $config->set('auth.providers.unresolvable', [
            'driver' => 'model',
            'model'  => UnresolvableIdentity::class,
        ]);
    }

    /**
     * Persist an identity with a hashed password.
     *
     * @return \Tests\Integration\Fixtures\UnresolvableIdentity
     */
    private function seedIdentity(): UnresolvableIdentity
    {
        $identity = new UnresolvableIdentity;
        $identity->forceFill([
            'email'    => 'misconfigured@example.test',
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ])->save();

        return $identity;
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

    /**
     * Resolve a fresh `api` JWT guard against a fresh request.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function freshGuard(): JwtGuard
    {
        app()->instance('request', Request::create('/sign-in', 'POST'));

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
