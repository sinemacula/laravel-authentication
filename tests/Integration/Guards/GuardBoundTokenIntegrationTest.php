<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\Coexist2dIdentity;
use Tests\Integration\Fixtures\DomainScopedModelProvider;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests proving tokens are bound to the guard that issued them.
 *
 * Every guard here uses the package-wide key map, the default configuration in
 * which the guards share a signing key, and none sets an issuer or audience.
 * Only the `grd` claim tells the guards' tokens apart, and refresh reloads the
 * device owner through the refreshing guard's own provider.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class GuardBoundTokenIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string Guard over `StubPrincipal`. */
    private const string STAFF_GUARD = 'staff';

    /** @var string Second guard over the same `StubPrincipal` model. */
    private const string SUPPORT_GUARD = 'support';

    /** @var string Guard over a different identity model. */
    private const string PARTNER_GUARD = 'partner';

    /** @var string Guard whose provider serves one email domain only. */
    private const string CUSTOMER_GUARD = 'customer';

    /** @var string Plaintext rotation id stored on seeded devices. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /**
     * Freeze the clocks, register the scoped provider driver, and create the
     * identity tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        IlluminateAuth::provider('domain_scoped', static fn (Application $app, array $config): DomainScopedModelProvider => new DomainScopedModelProvider(
            $app->make(Hasher::class),
            StubPrincipal::class,
        ));

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_2d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clocks and drop the identity tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('coexist_2d_identities');
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Two guards on one key map and one model: an access token issued by one
     * authenticates only on that guard.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokenAuthenticatesOnlyOnTheIssuingGuardWithSharedKeyAndModel(): void
    {
        $identity = $this->seedPrincipal('staff@staff.test');

        $token = $this->authManager()->jwt(self::STAFF_GUARD)->issueAccessToken($identity, $identity, null);

        self::assertTrue($this->guardForBearer(self::STAFF_GUARD, $token)->check());
        self::assertFalse($this->guardForBearer(self::SUPPORT_GUARD, $token)->check());
    }

    /**
     * Two guards on one key map and one model: a refresh token issued by one is
     * rejected as `token_invalid` by the other and still rotates on its own
     * guard.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshTokenRotatesOnlyOnTheIssuingGuardWithSharedKeyAndModel(): void
    {
        $identity = $this->seedPrincipal('staff@staff.test');
        $device   = $this->seedDevice($identity);

        $token = $this->authManager()->jwt(self::STAFF_GUARD)->issueRefreshToken($device, self::ROTATION_ID, $identity);

        Event::fake([RefreshFailed::class]);

        self::assertNull($this->guard(self::SUPPORT_GUARD)->refresh($token));

        Event::assertDispatched(
            RefreshFailed::class,
            static fn (RefreshFailed $event): bool => $event->guard === self::SUPPORT_GUARD
                && $event->reason                                   === RefreshFailureReason::TOKEN_INVALID,
        );

        self::assertNotNull($this->guard(self::STAFF_GUARD)->refresh($token));
    }

    /**
     * Two guards on one key map over different models: a token issued by one is
     * rejected by the other even when the other's model has a row with the same
     * id.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokenIsRejectedByAGuardOverAnotherModelWithTheSameKey(): void
    {
        $identity = $this->seedPrincipal('staff@staff.test');
        $partner  = $this->seedPartner();

        self::assertEquals($identity->getKey(), $partner->getKey());

        $token = $this->authManager()->jwt(self::STAFF_GUARD)->issueAccessToken($identity, $identity, null);

        self::assertFalse($this->guardForBearer(self::PARTNER_GUARD, $token)->check());
    }

    /**
     * Refresh reloads the device owner through the refreshing guard's provider:
     * when that provider maps the owner key to a row of another model, the
     * owner does not match and refresh fails with `authenticatable_missing`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshRejectsAnOwnerOfAnotherModelThatSharesTheKey(): void
    {
        $identity = $this->seedPrincipal('staff@staff.test');
        $device   = $this->seedDevice($identity);

        $this->seedPartner();

        $token = $this->authManager()->jwt(self::PARTNER_GUARD)->issueRefreshToken($device, self::ROTATION_ID);

        $this->assertRefreshFailsWith(self::PARTNER_GUARD, $token, RefreshFailureReason::AUTHENTICATABLE_MISSING);
    }

    /**
     * Refresh honours the guard provider's scope: an owner the provider does
     * not serve is rejected with `authenticatable_missing`, and one it does
     * serve rotates.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshHonoursTheGuardProviderScope(): void
    {
        $outside = $this->seedPrincipal('staff@staff.test');
        $inside  = $this->seedPrincipal('someone' . DomainScopedModelProvider::DOMAIN);

        $jwt = $this->authManager()->jwt(self::CUSTOMER_GUARD);

        $outsideToken = $jwt->issueRefreshToken($this->seedDevice($outside), self::ROTATION_ID);
        $insideToken  = $jwt->issueRefreshToken($this->seedDevice($inside), self::ROTATION_ID);

        $this->assertRefreshFailsWith(self::CUSTOMER_GUARD, $outsideToken, RefreshFailureReason::AUTHENTICATABLE_MISSING);

        $guard = $this->guard(self::CUSTOMER_GUARD);

        self::assertNotNull($guard->refresh($insideToken));
        self::assertTrue($inside->is($guard->user()));
    }

    /**
     * Configure four JWT guards that all use the package-wide key map.
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

        $config->set('auth.defaults.guard', self::STAFF_GUARD);

        foreach ([self::STAFF_GUARD, self::SUPPORT_GUARD] as $guard) {
            $config->set('auth.guards.' . $guard, ['driver' => 'jwt', 'provider' => 'principals']);
        }

        $config->set('auth.guards.' . self::PARTNER_GUARD, ['driver' => 'jwt', 'provider' => 'partners']);
        $config->set('auth.guards.' . self::CUSTOMER_GUARD, ['driver' => 'jwt', 'provider' => 'customers']);

        $config->set('auth.providers.principals', ['driver' => 'model', 'model' => StubPrincipal::class]);
        $config->set('auth.providers.partners', ['driver' => 'model', 'model' => Coexist2dIdentity::class]);
        $config->set('auth.providers.customers', ['driver' => 'domain_scoped']);
    }

    /**
     * Assert that refreshing on the guard returns `null` and dispatches
     * `RefreshFailed` with the expected reason.
     *
     * @param  string  $guard
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason  $reason
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertRefreshFailsWith(string $guard, string $token, RefreshFailureReason $reason): void
    {
        Event::fake([RefreshFailed::class]);

        self::assertNull($this->guard($guard)->refresh($token));

        Event::assertDispatched(
            RefreshFailed::class,
            static fn (RefreshFailed $event): bool => $event->guard === $guard && $event->reason === $reason,
        );
    }

    /**
     * Persist a `StubPrincipal` with the supplied email.
     *
     * @param  string  $email
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedPrincipal(string $email): StubPrincipal
    {
        $identity = new StubPrincipal;
        $identity->forceFill([
            'email'    => $email,
            'password' => 'hashed',
        ])->save();

        return $identity;
    }

    /**
     * Persist a `Coexist2dIdentity`; in a fresh table it takes id 1, the same
     * id as the first seeded `StubPrincipal`.
     *
     * @return \Tests\Integration\Fixtures\Coexist2dIdentity
     */
    private function seedPartner(): Coexist2dIdentity
    {
        $partner = new Coexist2dIdentity;
        $partner->forceFill([
            'email'    => 'partner@partner.test',
            'password' => 'hashed',
        ])->save();

        return $partner;
    }

    /**
     * Persist a device owned by the identity with a refresh digest for the
     * shared rotation id.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(Identity $identity): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return $device;
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
     * Resolve a fresh guard for an empty request.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(string $name): JwtGuard
    {
        app()->instance('request', Request::create('/refresh', 'POST'));

        $guard = $this->authManager()->guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }

    /**
     * Resolve a fresh guard for a request carrying the bearer token.
     *
     * @param  string  $name
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForBearer(string $name, string $token): JwtGuard
    {
        app()->instance('request', Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));

        $guard = $this->authManager()->guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
