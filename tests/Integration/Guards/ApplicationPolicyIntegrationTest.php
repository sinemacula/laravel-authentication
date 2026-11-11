<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use Tests\Concerns\InteractsWithTypedPrincipals;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\TestCase;

/**
 * Application policy over stored principals: every principal is admitted and
 * tokens and sessions follow the issuing guard's lifetimes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardApplicationPolicy::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(JwtTokenServiceFactory::class)]
#[CoversClass(JwtGuard::class)]
final class ApplicationPolicyIntegrationTest extends TestCase
{
    use InteractsWithTypedPrincipals;

    /** @var string Guard with lifetimes of its own. */
    private const string GUARD = 'api';

    /** @var string Guard on the package's lifetimes. */
    private const string OTHER_GUARD = 'other';

    /** @var string Password of seeded identities. */
    private const string PASSWORD = 'secret';

    /** @var string Plaintext rotation id of seeded sessions. */
    private const string ROTATION_ID = 'application-rotation';

    /**
     * Create the tables and the routes behind each guard's `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::createStrict(2026, 5, 1, 9, 0, 0));
        JWT::$timestamp = Carbon::now()->getTimestamp();

        self::createTypedPrincipalTables();

        foreach ([self::GUARD, self::OTHER_GUARD] as $guard) {
            Route::middleware('auth:' . $guard)->get('/' . $guard . '/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);
        }
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropTypedPrincipalTables();

        Carbon::setTestNow();
        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The package's application access admits every stored principal without
     * reading the tenant.
     *
     * @return void
     */
    public function testEveryStoredPrincipalIsAdmitted(): void
    {
        $access = app(ApplicationAccess::class);

        foreach ([['client_admin', 'staff'], [null, 'staff'], ['contractor', null], [null, null]] as [$type, $category]) {

            $membership = $this->seedMembership($type, $category);

            DB::enableQueryLog();
            DB::flushQueryLog();

            self::assertTrue($access->mayUse(self::GUARD, $membership));
            self::assertSame([], DB::getQueryLog());
            self::assertFalse($membership->relationLoaded('tenant'));
        }
    }

    /**
     * An access token expires after its guard's access lifetime.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAccessTokensLiveForTheirGuardsLifetime(): void
    {
        $membership = $this->seedMembership('client_staff', 'staff');
        $token      = $this->tokens()->issueAccessToken($membership->getIdentity(), $membership, null, null)->reveal();
        $other      = $this->tokens(self::OTHER_GUARD)->issueAccessToken($membership->getIdentity(), $membership, null, null)->reveal();

        $this->assertExpiresInMinutes(2, $token);
        $this->assertExpiresInMinutes(15, $other, self::OTHER_GUARD);
        $this->withToken($token)->getJson('/api/me')->assertOk()->assertExactJson(['principal' => $membership->getKey()]);

        Carbon::setTestNow(Carbon::now()->addMinutes(3));
        JWT::$timestamp = Carbon::now()->getTimestamp();

        $this->withToken($token)->getJson('/api/me')->assertUnauthorized();
        $this->withToken($other)->getJson('/other/me')->assertOk()->assertExactJson(['principal' => $membership->getKey()]);
    }

    /**
     * A session and its refresh follow the guard's lifetimes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSessionsAndRefreshedTokensFollowTheGuardsLifetimes(): void
    {
        $membership = $this->seedMembership('client_staff', null);
        $identity   = $membership->getIdentity();
        $lifetimes  = app(ApplicationPolicy::class)->lifetimes(self::GUARD);
        $absolute   = $lifetimes->absoluteDeadline(Carbon::now());

        self::assertInstanceOf(TypedIdentity::class, $identity);
        self::assertNotNull($absolute);
        self::assertSame(Carbon::now()->addDay()->getTimestamp(), $absolute->getTimestamp());

        $record = new Session;
        $record->forceFill([
            'principal_type'       => PrincipalReference::type($membership),
            'principal_id'         => PrincipalReference::id($membership),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'guard'                => self::GUARD,
            'sign_in_method'       => 'password',
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
            'signed_in_at'         => Carbon::now(),
            'idle_expires_at'      => $lifetimes->idleDeadline(Carbon::now(), $absolute),
            'absolute_expires_at'  => $absolute,
        ])->save();

        $refreshToken = $this->tokens()->issueRefreshToken($record, self::ROTATION_ID, $membership)->reveal();
        $refreshed    = Auth::manager()->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $refreshed);

        $result = GuardSessions::of($refreshed)->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient())->session?->tokens;

        self::assertNotNull($result);
        $this->assertExpiresInMinutes(2, $result->accessToken->reveal());
        self::assertSame($absolute->getTimestamp(), $this->claims($refreshToken, TokenType::REFRESH)[Claims::EXPIRES_AT->value]);
    }

    /**
     * No token the guard issues carries a principal type.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoIssuedTokenCarriesAPrincipalType(): void
    {
        $first  = $this->seedMembership('client_admin', 'staff');
        $second = TypedMembership::query()->create(['identity_id' => $first->identity_id, 'tenant_id' => null, 'type' => 'service']);

        $sessions = Auth::sessions(self::GUARD);
        $signedIn = $sessions->start(UndescribedFirstFactor::of($first->getIdentity()), $first, 'password', self::requestContext())->session;

        self::assertNotNull($signedIn);

        Auth::forgetGuards();

        $refreshed = Auth::sessions(self::GUARD)->refresh(self::bodyToken($signedIn->tokens), self::requestClient())->session;

        self::assertNotNull($refreshed);

        Auth::forgetGuards();

        $switched = Auth::sessions(self::GUARD)->switchTo(
            self::bodyToken($refreshed->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        )->session;

        self::assertNotNull($switched);
        self::assertSame($second->getKey(), $switched->principal->getPrincipalIdentifier());

        foreach ([$signedIn, $refreshed, $switched] as $session) {
            self::assertArrayNotHasKey('pty', $this->claims($session->tokens->accessToken->reveal()));
            self::assertArrayNotHasKey('pty', $this->claims(self::bodyRefreshToken($session->tokens), TokenType::REFRESH));
        }
    }

    /**
     * A `pty` claim on a signed access token is ignored.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenCarryingAPrincipalTypeAuthenticates(): void
    {
        $membership = $this->seedMembership('client_staff', 'staff');
        $claims     = $this->claims($this->tokens()->issueAccessToken($membership->getIdentity(), $membership, null, null)->reveal());
        $kid        = config('authentication.jwt.active_kid');

        self::assertIsString($kid);

        $key = config('authentication.jwt.keys.' . $kid);

        self::assertIsString($key);

        $legacy = JWT::encode([...$claims, 'pty' => 'contractor'], $key, 'HS256', $kid, ['typ' => TokenType::ACCESS->value]);

        $this->withToken($legacy)->getJson('/api/me')->assertOk()->assertExactJson(['principal' => $membership->getKey()]);
    }

    /**
     * Configure the guards and their lifetimes.
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
            'driver'      => 'jwt',
            'provider'    => 'typed',
            'application' => ['methods' => ['password']],
            'jwt'         => ['access_ttl_minutes' => 2, 'refresh_absolute_ttl_minutes' => 60 * 24],
        ]);
        $config->set('auth.guards.' . self::OTHER_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'typed',
            'jwt'      => ['access_ttl_minutes' => 15, 'refresh_absolute_ttl_minutes' => 60 * 24 * 30],
        ]);
        $config->set('auth.providers.typed', ['driver' => 'model', 'model' => TypedIdentity::class]);
    }

    /**
     * Persist an identity with one typed membership and return the membership
     * without its tenant.
     *
     * @param  ?string  $type
     * @param  ?string  $category
     * @return \Tests\Integration\Fixtures\TypedMembership
     */
    private function seedMembership(?string $type, ?string $category): TypedMembership
    {
        $identity = TypedIdentity::query()->create(['email' => 'application@example.test', 'password' => bcrypt(self::PASSWORD)]);
        $tenant   = $category === null ? null : TypedTenant::query()->create(['category' => $category]);

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
     * Assert the access token expires the given number of minutes from now.
     *
     * @param  int  $minutes
     * @param  string  $token
     * @param  string  $guard
     * @return void
     */
    private function assertExpiresInMinutes(int $minutes, string $token, string $guard = self::GUARD): void
    {
        self::assertSame(Carbon::now()->addMinutes($minutes)->getTimestamp(), $this->claims($token, TokenType::ACCESS, $guard)[Claims::EXPIRES_AT->value]);
    }

    /**
     * The guard's token service.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(string $guard = self::GUARD): JwtTokenService
    {
        return Auth::manager()->jwt($guard);
    }

    /**
     * Parse a token of the guard.
     *
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @param  string  $guard
     * @return array<string, mixed>
     */
    private function claims(#[\SensitiveParameter] string $token, TokenType $type = TokenType::ACCESS, string $guard = self::GUARD): array
    {
        $claims = $this->tokens($guard)->parse($token, $type);

        self::assertIsArray($claims);

        return $claims;
    }
}
