<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Concerns\ProvidesType;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use Tests\Concerns\InteractsWithDevices;
use Tests\Concerns\InteractsWithTypedPrincipals;
use Tests\Integration\Fixtures\ColumnSelectingMembershipResolver;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\TestCase;

/**
 * Integration tests for a principal loaded without its type column: the guard
 * fails closed on sign-in, refresh and bearer requests rather than reading the
 * principal as untyped and giving it its tenant's type, which the guard's
 * audience would admit.
 *
 * The `api` guard admits only `staff` principals and resolves memberships
 * through `ColumnSelectingMembershipResolver`, which selects `id`,
 * `identity_id` and `tenant_id` only. The seeded membership is a `customer`
 * inside a `staff` tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardAudiencePolicy::class)]
#[CoversClass(JwtGuard::class)]
#[CoversTrait(ProvidesType::class)]
final class PartiallySelectedPrincipalTypeIntegrationTest extends TestCase
{
    use InteractsWithDevices, InteractsWithTypedPrincipals;

    /** @var string Guard the tests authenticate with. */
    private const string GUARD = 'api';

    /** @var string Password of the seeded identity. */
    private const string PASSWORD = 'secret';

    /** @var string Plaintext rotation id of the seeded device. */
    private const string ROTATION_ID = 'partial-type-rotation';

    /** @var string Message of the exception an unloaded type raises. */
    private const string UNLOADED = 'Cannot read the type of ' . TypedMembership::class . ': its `type` attribute is not loaded.';

    /**
     * Create the typed tables and the route behind the `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createTypedPrincipalTables();

        Route::middleware('auth:' . self::GUARD)->get('/type', static fn (): array => ['type' => Auth::type()]);
    }

    /**
     * Drop the typed tables.
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
     * Signing in through the session service or `attempt()` throws instead of
     * admitting the customer as staff, and writes no session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInFailsClosedOnAPrincipalLoadedWithoutItsType(): void
    {
        $this->seedMembership();

        $credentials = ['email' => 'typed@example.test', 'password' => self::PASSWORD];

        $this->assertUnloadedType(fn (): mixed => Auth::sessions($this->guard()->getName())->signIn('password', $credentials));
        $this->assertUnloadedType(fn (): mixed => $this->guard()->attempt($credentials));

        self::assertSame(0, Device::query()->count());
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * A refresh throws before it rotates the device or issues a pair.
     *
     * @return void
     */
    public function testARefreshFailsClosedOnAPrincipalLoadedWithoutItsType(): void
    {
        $membership = $this->seedMembership();
        $identity   = $membership->getIdentity();

        self::assertInstanceOf(TypedIdentity::class, $identity);

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $membership);

        $this->assertUnloadedType(fn (): mixed => $this->guard()->refresh($refreshToken));

        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), Device::query()->whereKey($device->getKey())->value('refresh_key'));
    }

    /**
     * A bearer request whose principal the resolver loads without its type
     * throws instead of reporting the tenant's type.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testABearerRequestFailsClosedOnAPrincipalLoadedWithoutItsType(): void
    {
        $membership = $this->seedMembership();
        $token      = $this->tokens()->issueAccessToken($membership->getIdentity(), $membership, null);

        $this->withoutExceptionHandling();

        $this->assertUnloadedType(fn (): mixed => $this->withToken($token)->getJson('/type'));
    }

    /**
     * Configure the guard's audience and the column-selecting resolver.
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
            'driver'             => 'jwt',
            'provider'           => 'typed',
            'principal_resolver' => ColumnSelectingMembershipResolver::class,
            'audience'           => ['principal_types' => ['staff']],
        ]);
        $config->set('auth.providers.typed', ['driver' => 'model', 'model' => TypedIdentity::class]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity with one `customer` membership, fully loaded, inside
     * a `staff` tenant.
     *
     * @return \Tests\Integration\Fixtures\TypedMembership
     */
    private function seedMembership(): TypedMembership
    {
        $identity = TypedIdentity::query()->create([
            'email'    => 'typed@example.test',
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ]);

        $tenant = TypedTenant::query()->create(['category' => 'staff']);

        return TypedMembership::query()->create([
            'identity_id' => $identity->getKey(),
            'tenant_id'   => $tenant->getKey(),
            'type'        => 'customer',
        ]);
    }

    /**
     * Assert the callback throws because the principal's type is not loaded.
     *
     * @param  \Closure(): mixed  $callback
     * @return void
     */
    private function assertUnloadedType(\Closure $callback): void
    {
        try {
            $callback();
        } catch (\LogicException $e) {
            self::assertStringStartsWith(self::UNLOADED, $e->getMessage());

            return;
        }

        self::fail('Expected a principal loaded without its type to be refused.');
    }

    /**
     * Resolve the guard afresh.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        Auth::forgetGuards();

        $guard = Auth::manager()->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }

    /**
     * The guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        return Auth::manager()->jwt(self::GUARD);
    }
}
