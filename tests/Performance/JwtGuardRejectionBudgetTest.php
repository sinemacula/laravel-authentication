<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Firebase\JWT\JWT;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\BearerForms;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Query-budget and timing contracts for rejected bearer and refresh tokens: a
 * request whose token fails after a lookup is resolved once however often the
 * guard is asked, a bearer token for another guard or missing a required claim
 * is rejected before any query, and such a refresh token before any session or
 * identity query, touching only the IP address's refresh limit; an API key on a
 * route that lists an `api_key` guard too costs the `jwt` guard nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class JwtGuardRejectionBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessionRecords;

    /** @var string Guard under test. */
    private const string GUARD = 'api';

    /** @var string Second guard over the same identities and signing key. */
    private const string OTHER_GUARD = 'other_api';

    /** @var string An `api_key` guard over the same identities. */
    private const string KEY_GUARD = 'keys';

    /** @var string Plaintext rotation id stored on the seeded session. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var int Bearer resolutions timed by the timing contract. */
    private const int TIMED_REQUESTS = 50;

    /** @var int Generous ceiling for those resolutions, in nanoseconds (100 ms each). */
    private const int TIMED_CEILING_NANOSECONDS = self::TIMED_REQUESTS * 100000000;

    /** @var list<?string> The guard of each `AuthenticationFailed` dispatched since recording began. */
    private array $failedGuards = [];

    /**
     * Provision the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('integration_identities');

        parent::tearDown();
    }

    /**
     * Rows of `[rejection, reads]`: bearer tokens that fail after reading the
     * database, and the reads one resolution costs.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideTokensRejectedAfterALookup(): iterable
    {
        yield from [
            'unknown subject'         => ['unknown', 1],
            'inactive identity'       => ['inactive', 1],
            'revoked session'         => ['revoked', 2],
            'idle deadline reached'   => ['idle', 2],
            'absolute deadline past'  => ['absolute', 2],
            'principal switched away' => ['switched', 2],
            'tenant switched away'    => ['tenant', 2],
            'pending session'         => ['pending', 2],
        ];
    }

    /**
     * A bearer token that fails after a lookup is resolved once per request:
     * asking the guard again through every accessor costs no further query. A
     * revoked, ended or pending session, or one that switched to another
     * principal or tenant, is rejected from the row the session lookup already
     * loaded.
     *
     * @param  string  $rejection
     * @param  int  $reads
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    #[DataProvider('provideTokensRejectedAfterALookup')]
    public function testRejectedBearerTokenIsResolvedOncePerRequest(string $rejection, int $reads): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);
        $token    = $this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal();

        match ($rejection) {
            'unknown'  => $identity->delete(),
            'inactive' => $identity->forceFill(['is_active' => false])->save(),
            'idle'     => $session->forceFill(['idle_expires_at' => $this->now])->save(),
            'absolute' => $session->forceFill(['absolute_expires_at' => $this->now->copy()->subSecond()])->save(),
            'switched' => $session->forceFill(['principal_id' => 'another principal', 'switched_at' => $this->now])->save(),
            'tenant'   => $session->forceFill(['tenant_id' => 'another tenant', 'switched_at' => $this->now])->save(),
            'pending'  => $session->forceFill(['status' => 'pending', 'requires' => '["mfa"]'])->save(),
            default    => $session->forceFill(['revoked_at' => $this->now])->save(),
        };

        $this->bindRequestWithBearer('/perf/rejected', $token);

        $guard = $this->freshJwtGuard(self::GUARD);

        $outcomes = $this->assertQueryBudget($reads, 0, static function () use ($guard): array {

            $outcomes = [];

            for ($round = 0; $round < 2; $round++) {
                $outcomes[] = $guard->check();
                $outcomes[] = $guard->user();
                $outcomes[] = $guard->id();
                $outcomes[] = $guard->identity();
                $outcomes[] = $guard->principal();
                $outcomes[] = $guard->session();
                $outcomes[] = $guard->tenant();
            }

            return $outcomes;
        });

        $signedOut = [false, null, null, null, null, null, null];

        self::assertSame([...$signedOut, ...$signedOut], $outcomes);
    }

    /**
     * A bearer token issued by another guard is rejected while parsing, before
     * any query, although both guards share the signing key and identities.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerTokenFromAnotherGuardUsesNoQueries(): void
    {
        $identity = $this->seedIdentity();
        $token    = $this->tokens(self::OTHER_GUARD)->issueAccessToken($identity, $identity, null, null)->reveal();

        $this->bindRequestWithBearer('/perf/foreign', $token);

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertFalse($this->assertQueryBudget(0, 0, static fn (): bool => $guard->check()));
    }

    /**
     * A correctly signed bearer token missing a required claim is rejected
     * while parsing, before any query.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testBearerTokenMissingARequiredClaimUsesNoQueries(): void
    {
        $identity = $this->seedIdentity();

        $this->bindRequestWithBearer('/perf/missing-claim', $this->encode([
            Claims::SUBJECT->value      => (string) $identity->getKey(), // @phpstan-ignore cast.string
            Claims::SUBJECT_TYPE->value => 'person',
        ]));

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertFalse($this->assertQueryBudget(0, 0, static fn (): bool => $guard->check()));
    }

    /**
     * A bearer credential in API key form, on a route whose `auth` middleware
     * lists an `api_key` guard beside the `jwt` guard, is that guard's: the
     * `jwt` guard parses nothing, queries nothing and reports nothing, and the
     * route costs only the key guard's one lookup.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnApiKeyOnARouteListingAKeyGuardCostsTheJwtGuardNothing(): void
    {
        $key = 'ak_zzzzzzzzzzzzzzzz_' . str_repeat('a', 40);

        $this->bindRequestWithBearer('/perf/key', $key);

        $request = request();
        $request->attributes->set(BearerForms::ROUTE_GUARDS, [self::GUARD, self::KEY_GUARD]);

        $guard = $this->freshJwtGuard(self::GUARD);

        Event::listen(AuthenticationFailed::class, function (AuthenticationFailed $event): void {
            $this->failedGuards[] = $event->context->guard;
        });

        self::assertFalse($this->assertQueryBudget(0, 0, static fn (): bool => $guard->check()));
        self::assertSame([], $this->failedGuards);

        PackageAuth::manager()->forgetGuards();

        $this->assertQueryBudget(1, 0, function () use ($request): void {
            try {
                $this->app?->make(Authenticate::class)->handle($request, static fn (): Response => new Response, self::GUARD, self::KEY_GUARD);
            } catch (AuthenticationException) {
                return;
            }

            self::fail('Expected the key to be refused.');
        });

        self::assertSame([self::KEY_GUARD], $this->failedGuards);
    }

    /**
     * A refresh token issued by another guard is rejected while parsing, before
     * any session or identity query. It names no session the guard can trust,
     * so only the IP address's limit is read and, as a failure, counted: on a
     * fresh window an update that changes nothing and the insert that creates
     * the counter.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshTokenFromAnotherGuardTouchesOnlyTheIpAddressLimit(): void
    {
        $identity = $this->seedIdentity();
        $token    = $this->tokens(self::OTHER_GUARD)->issueRefreshToken($this->seedSession($identity), self::ROTATION_ID, $identity)->reveal();

        $guard = $this->refreshGuard();

        self::assertNull($this->assertQueryBudget(1, 2, static fn (): mixed => GuardSessions::of($guard)->refresh($token))->session);
    }

    /**
     * A correctly signed refresh token missing its `sid` is rejected while
     * parsing, before any session or identity query, and counted against the IP
     * address only.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshTokenMissingARequiredClaimTouchesOnlyTheIpAddressLimit(): void
    {
        $token = $this->encode([], TokenType::REFRESH);
        $guard = $this->refreshGuard();

        self::assertNull($this->assertQueryBudget(1, 2, static fn (): mixed => GuardSessions::of($guard)->refresh($token))->session);
    }

    /**
     * Resolving a session-bearing bearer request, with every write-connection
     * pin it takes, stays far inside a generous time ceiling. The phpbench
     * harness (`benchmarks/Runtime/JwtGuardBench.php`, `composer bench`)
     * measures the same path precisely; this guards against a pathological
     * regression such as a reconnect per pin.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \Random\RandomException
     */
    public function testBearerResolutionStaysWithinAGenerousTimeCeiling(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);
        $token    = $this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal();

        $session->forceFill(['last_used_at' => $this->now])->save();

        $started = hrtime(true);

        for ($request = 0; $request < self::TIMED_REQUESTS; $request++) {
            $this->bindRequestWithBearer('/perf/timed', $token);

            self::assertTrue($this->freshJwtGuard(self::GUARD)->check());
        }

        self::assertLessThan(self::TIMED_CEILING_NANOSECONDS, hrtime(true) - $started);
    }

    /**
     * Configure two guards over the same identities and signing key.
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

        foreach ([self::GUARD, self::OTHER_GUARD] as $guard) {
            $config->set('auth.guards.' . $guard, [
                'driver'   => 'jwt',
                'provider' => 'integration_identities',
            ]);
        }

        $config->set('auth.guards.' . self::KEY_GUARD, ['driver' => 'api_key', 'provider' => 'integration_identities']);

        $config->set('auth.providers.integration_identities', [
            'driver' => 'model',
            'model'  => IntegrationIdentity::class,
        ]);

        $config->set('authentication.session.last_used_throttle_seconds', 60);
    }

    /**
     * Persist an active identity.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private function seedIdentity(): IntegrationIdentity
    {
        $identity            = new IntegrationIdentity;
        $identity->email     = 'rejected@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        return $identity;
    }

    /**
     * Persist a live session for the identity holding the stored rotation.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(IntegrationIdentity $identity): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return $session;
    }

    /**
     * Resolve the token service of a guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(string $guard = self::GUARD): JwtTokenService
    {
        $tokens = PackageAuth::jwt($guard);

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * Sign a payload of the type for this guard with the configured key, adding
     * only the timing, id, issuer, audience and guard claims to the supplied
     * ones.
     *
     * @param  array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return string
     */
    private function encode(array $claims, TokenType $type = TokenType::ACCESS): string
    {
        $issuedAt = $this->now->getTimestamp();

        return JWT::encode([
            Claims::ISSUER->value     => self::JWT_ISSUER,
            Claims::AUDIENCE->value   => self::JWT_AUDIENCE,
            Claims::CLIENT_ID->value  => self::GUARD,
            Claims::ISSUED_AT->value  => $issuedAt,
            Claims::EXPIRES_AT->value => $issuedAt + 600,
            Claims::JWT_ID->value     => 'token-id',
            ...$claims,
        ], 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid', ['typ' => $type->value]);
    }

    /**
     * Resolve a fresh guard for a refresh request.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function refreshGuard(): JwtGuard
    {
        app()->instance('request', Request::create('/refresh', 'POST'));

        return $this->freshJwtGuard(self::GUARD);
    }
}
