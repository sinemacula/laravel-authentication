<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\PrincipalType;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Concerns\InteractsWithTypedPrincipals;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\TestCase;

/**
 * Integration tests for the principal type: a principal's own type, else its
 * tenant's, carried in the access token's `pty` claim and returned live by
 * `Auth::type()` through the `auth` middleware.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalType::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(JwtGuard::class)]
final class PrincipalTypeIntegrationTest extends TestCase
{
    use InteractsWithDevices, InteractsWithTypedPrincipals;

    /** @var string Guard the tests authenticate with. */
    private const string GUARD = 'api';

    /** @var string Plaintext rotation id of the seeded device. */
    private const string ROTATION_ID = 'principal-type-rotation';

    /**
     * Create the typed identity, membership, and tenant tables and the route
     * that reports the request's principal type.
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
     * A membership with a type of its own is that type, in the token and on the
     * request, even inside a tenant of another type.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testPrincipalsOwnTypeWinsOverItsTenantsInTheTokenAndOnTheRequest(): void
    {
        $membership = $this->seedMembership('client_admin', 'staff');
        $token      = $this->tokens()->issueAccessToken($membership->getIdentity(), $membership, null);

        self::assertSame('client_admin', $this->claims($token)[Claims::PRINCIPAL_TYPE->value]);

        $this->withToken($token)->getJson('/type')->assertOk()->assertExactJson(['type' => 'client_admin']);
    }

    /**
     * A membership without a type of its own takes its tenant's.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testPrincipalWithoutATypeTakesItsTenantsType(): void
    {
        $membership = $this->seedMembership(null, 'staff');
        $token      = $this->tokens()->issueAccessToken($membership->getIdentity(), $membership, null);

        self::assertSame('staff', $this->claims($token)[Claims::PRINCIPAL_TYPE->value]);

        $this->withToken($token)->getJson('/type')->assertOk()->assertExactJson(['type' => 'staff']);
    }

    /**
     * A membership with no type and no typed tenant has none: its tokens carry
     * no `pty` claim and still authenticate.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testPrincipalWithNoTypeAnywhereHasNoClaimAndNoType(): void
    {
        $membership = $this->seedMembership(null, null);
        $token      = $this->tokens()->issueAccessToken($membership->getIdentity(), $membership, null);

        self::assertArrayNotHasKey(Claims::PRINCIPAL_TYPE->value, $this->claims($token));

        $this->withToken($token)->getJson('/type')->assertOk()->assertExactJson(['type' => null]);
    }

    /**
     * `Auth::type()` reads the principal as it is now, not the claim the token
     * was issued with: a type changed after issue shows at once.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTypeOnTheRequestIsReadLiveNotFromTheClaim(): void
    {
        $membership = $this->seedMembership('client_admin', null);
        $token      = $this->tokens()->issueAccessToken($membership->getIdentity(), $membership, null);

        TypedMembership::query()->whereKey($membership->getKey())->update(['type' => 'client_staff']);

        self::assertSame('client_admin', $this->claims($token)[Claims::PRINCIPAL_TYPE->value]);

        $this->withToken($token)->getJson('/type')->assertOk()->assertExactJson(['type' => 'client_staff']);
    }

    /**
     * A refresh issues an access token with the principal's type as it is at
     * the refresh, while the refresh token itself carries no type.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshIssuesTheCurrentTypeOnTheAccessTokenOnly(): void
    {
        $membership = $this->seedMembership('client_admin', null);
        $identity   = $membership->getIdentity();

        self::assertInstanceOf(TypedIdentity::class, $identity);

        $device = new Device;
        $device->forceFill([
            ...self::liveSession('api', $membership),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        $refreshToken = $this->tokens()->issueRefreshToken($device, self::ROTATION_ID, $membership);

        TypedMembership::query()->whereKey($membership->getKey())->update(['type' => 'client_staff']);

        $guard = Auth::manager()->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        $result = GuardSessions::of($guard)->refresh($refreshToken)->session?->tokens;

        self::assertNotNull($result);
        self::assertSame('client_staff', $this->claims($result->accessToken)[Claims::PRINCIPAL_TYPE->value]);
        self::assertArrayNotHasKey(Claims::PRINCIPAL_TYPE->value, $this->claims($result->refreshToken, TokenType::REFRESH));
        self::assertSame('client_staff', $guard->type());
    }

    /**
     * Configure the guard over the typed identities.
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
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'typed']);
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
        $identity = TypedIdentity::query()->create([
            'email'    => 'typed@example.test',
            'password' => app(Hasher::class)->make('secret'),
        ]);

        $tenant = $tenantType === null ? null : TypedTenant::query()->create(['category' => $tenantType]);

        return TypedMembership::query()->create([
            'identity_id' => $identity->getKey(),
            'tenant_id'   => $tenant?->getKey(),
            'type'        => $type,
        ]);
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
