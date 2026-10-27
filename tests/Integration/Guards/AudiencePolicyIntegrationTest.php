<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\TestCase;

/**
 * Integration tests for a guard's audience: eligibility read from stored
 * principals and tenants, and lifetimes per principal type on the tokens the
 * guard issues and the `auth` middleware accepts.
 *
 * The `api` guard admits the `staff` and `client_staff` types, and gives
 * `client_staff` two-minute access tokens and a one-day session against the
 * guard's fifteen minutes and thirty days.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardAudiencePolicy::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(JwtTokenServiceFactory::class)]
#[CoversClass(JwtGuard::class)]
final class AudiencePolicyIntegrationTest extends TestCase
{
    /** @var string Guard the tests authenticate with. */
    private const string GUARD = 'api';

    /** @var string Plaintext rotation id of seeded devices. */
    private const string ROTATION_ID = 'audience-rotation';

    /**
     * Create the typed tables and the route behind the `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::createStrict(2026, 5, 1, 9, 0, 0));
        JWT::$timestamp = Carbon::now()->getTimestamp();

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

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['type' => Auth::type()]);
    }

    /**
     * Drop the typed tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('typed_memberships');
        Schema::dropIfExists('typed_tenants');
        Schema::dropIfExists('typed_identities');

        Carbon::setTestNow();
        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Eligibility reads the type from the stored rows: a member of a `staff`
     * tenant and a `client_staff` membership are admitted, while a
     * `client_admin` membership and an untyped member of an untyped tenant are
     * refused.
     *
     * @return void
     */
    public function testEligibilityFollowsTheStoredPrincipalAndTenantTypes(): void
    {
        $policy = app(AudiencePolicy::class);

        self::assertNull($this->admit($policy, $this->seedMembership(null, 'staff')));
        self::assertNull($this->admit($policy, $this->seedMembership('client_staff', 'staff')));
        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->admit($policy, $this->seedMembership('client_admin', 'staff')));
        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->admit($policy, $this->seedMembership(null, null)));
    }

    /**
     * An access token for a `client_staff` principal expires after its type's
     * two minutes, so the middleware rejects it while a `staff` token issued at
     * the same moment, on the guard's fifteen minutes, still passes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokensLiveForTheirPrincipalTypesLifetime(): void
    {
        $clientStaff = $this->seedMembership('client_staff', null);
        $staff       = $this->seedMembership(null, 'staff');

        $clientStaffToken = $this->tokens()->issueAccessToken($clientStaff->getIdentity(), $clientStaff, null);
        $staffToken       = $this->tokens()->issueAccessToken($staff->getIdentity(), $staff, null);

        $this->assertExpiresInMinutes(2, $clientStaffToken);
        $this->assertExpiresInMinutes(15, $staffToken);
        $this->withToken($clientStaffToken)->getJson('/me')->assertOk()->assertExactJson(['type' => 'client_staff']);

        Carbon::setTestNow(Carbon::now()->addMinutes(3));
        JWT::$timestamp = Carbon::now()->getTimestamp();

        $this->withToken($clientStaffToken)->getJson('/me')->assertUnauthorized();
        $this->withToken($staffToken)->getJson('/me')->assertOk()->assertExactJson(['type' => 'staff']);
    }

    /**
     * A device stamped from the policy's lifetimes for a `client_staff`
     * principal gets that type's session, and a refresh of it returns an access
     * token on that type's access lifetime.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSessionsAndRefreshedTokensFollowThePrincipalTypesLifetimes(): void
    {
        $membership = $this->seedMembership('client_staff', null);
        $identity   = $membership->getIdentity();
        $lifetimes  = app(AudiencePolicy::class)->lifetimes(self::GUARD, $membership);
        $absolute   = $lifetimes->absoluteDeadline(Carbon::now());

        self::assertInstanceOf(TypedIdentity::class, $identity);
        self::assertSame(Carbon::now()->addDay()->getTimestamp(), $absolute->getTimestamp());

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'guard'                => self::GUARD,
            'sign_in_method'       => 'password',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'idle_expires_at'      => $lifetimes->idleDeadline(Carbon::now(), $absolute),
            'absolute_expires_at'  => $absolute,
        ])->save();

        $refreshToken = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $membership);
        $refreshed    = Auth::manager()->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $refreshed);

        $result = $refreshed->refresh($refreshToken);

        self::assertNotNull($result);
        $this->assertExpiresInMinutes(2, $result->accessToken);
        self::assertSame($absolute->getTimestamp(), $this->claims($refreshToken, TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
    }

    /**
     * Configure the guard's audience and per-type lifetimes.
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
            'provider' => 'typed',
            'audience' => ['principal_types' => ['staff', 'client_staff']],
            'jwt'      => [
                'by_principal_type' => [
                    'client_staff' => ['access_ttl_minutes' => 2, 'refresh_absolute_ttl_minutes' => 60 * 24],
                ],
            ],
        ]);
        $config->set('auth.providers.typed', ['driver' => 'model', 'model' => TypedIdentity::class]);
    }

    /**
     * Persist an identity with one membership of the given type, in a tenant of
     * the given type when one is given.
     *
     * @param  ?string  $type
     * @param  ?string  $tenantType
     * @return \Tests\Integration\Fixtures\TypedMembership
     */
    private function seedMembership(?string $type, ?string $tenantType): TypedMembership
    {
        $identity = TypedIdentity::query()->create(['email' => 'audience@example.test', 'password' => 'unused']);
        $tenant   = $tenantType === null ? null : TypedTenant::query()->create(['category' => $tenantType]);

        $membership = TypedMembership::query()->create([
            'identity_id' => $identity->getKey(),
            'tenant_id'   => $tenant?->getKey(),
            'type'        => $type,
        ]);

        $fresh = TypedMembership::query()->find($membership->getKey());

        self::assertInstanceOf(TypedMembership::class, $fresh);

        return $fresh;
    }

    /**
     * Ask the policy to admit the membership to the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $policy
     * @param  \Tests\Integration\Fixtures\TypedMembership  $membership
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason
     */
    private function admit(AudiencePolicy $policy, TypedMembership $membership): ?SignInFailureReason
    {
        return $policy->admit(self::GUARD, $membership->getIdentity(), $membership, null);
    }

    /**
     * Assert the access token expires the given number of minutes from now.
     *
     * @param  int  $minutes
     * @param  string  $token
     * @return void
     */
    private function assertExpiresInMinutes(int $minutes, string $token): void
    {
        self::assertSame(Carbon::now()->addMinutes($minutes)->getTimestamp(), $this->claims($token)[Claims::EXPIRES_AT->value]);
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

    /**
     * Parse a token of the guard.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array<string, mixed>
     */
    private function claims(string $token, TokenType $type = TokenType::ACCESS): array
    {
        $claims = $this->tokens()->parse($token, $type);

        self::assertIsArray($claims);

        return $claims;
    }
}
