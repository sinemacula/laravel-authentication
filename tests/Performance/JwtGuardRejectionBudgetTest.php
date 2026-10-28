<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Query-budget and timing contracts for rejected bearer and refresh tokens: a
 * request whose token fails after a lookup is resolved once however often the
 * guard is asked, a bearer token for another guard or missing a required claim
 * is rejected before any query, and such a refresh token before any device or
 * identity query, touching only the IP address's refresh limit.
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
    use InteractsWithDevices;

    /** @var string Guard under test. */
    private const string GUARD = 'api';

    /** @var string Second guard over the same identities and signing key. */
    private const string OTHER_GUARD = 'other_api';

    /** @var string Plaintext rotation id stored on the seeded device. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var int Bearer resolutions timed by the timing contract. */
    private const int TIMED_REQUESTS = 50;

    /** @var int Generous ceiling for those resolutions, in nanoseconds (100 ms each). */
    private const int TIMED_CEILING_NANOSECONDS = self::TIMED_REQUESTS * 100000000;

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
            'unknown subject'        => ['unknown', 1],
            'inactive identity'      => ['inactive', 1],
            'revoked device'         => ['revoked', 2],
            'idle deadline reached'  => ['idle', 2],
            'absolute deadline past' => ['absolute', 2],
        ];
    }

    /**
     * A bearer token that fails after a lookup is resolved once per request:
     * asking the guard again through every accessor costs no further query. A
     * revoked or ended device is rejected from the row the device lookup
     * already loaded.
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
        $device   = $this->seedDevice($identity);
        $token    = $this->tokens()->issueAccessToken($identity, $identity, $device);

        match ($rejection) {
            'unknown'  => $identity->delete(),
            'inactive' => $identity->forceFill(['is_active' => false])->save(),
            'idle'     => $device->forceFill(['idle_expires_at' => $this->now])->save(),
            'absolute' => $device->forceFill(['absolute_expires_at' => $this->now->copy()->subSecond()])->save(),
            default    => $device->forceFill(['revoked_at' => $this->now])->save(),
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
                $outcomes[] = $guard->device();
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
        $token    = $this->tokens(self::OTHER_GUARD)->issueAccessToken($identity, $identity, null);

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
            Claims::SUBJECT->value => (string) $identity->getKey(), // @phpstan-ignore cast.string
            Claims::TYPE->value    => TokenType::ACCESS->value,
        ]));

        $guard = $this->freshJwtGuard(self::GUARD);

        self::assertFalse($this->assertQueryBudget(0, 0, static fn (): bool => $guard->check()));
    }

    /**
     * A refresh token issued by another guard is rejected while parsing, before
     * any device or identity query. It names no device the guard can trust, so
     * only the IP address's limit is read and, as a failure, counted: on a
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
        $token    = $this->tokens(self::OTHER_GUARD)->issueRefreshToken($this->seedDevice($identity), self::ROTATION_ID, $identity);

        $guard = $this->refreshGuard();

        self::assertNull($this->assertQueryBudget(1, 2, static fn (): mixed => $guard->refresh($token)));
    }

    /**
     * A correctly signed refresh token missing its `did` is rejected while
     * parsing, before any device or identity query, and counted against the IP
     * address only.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testRefreshTokenMissingARequiredClaimTouchesOnlyTheIpAddressLimit(): void
    {
        $token = $this->encode([Claims::TYPE->value => TokenType::REFRESH->value]);
        $guard = $this->refreshGuard();

        self::assertNull($this->assertQueryBudget(1, 2, static fn (): mixed => $guard->refresh($token)));
    }

    /**
     * Resolving a device-bearing bearer request, with every write-connection
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
        $device   = $this->seedDevice($identity);
        $token    = $this->tokens()->issueAccessToken($identity, $identity, $device);

        $device->forceFill(['last_used_at' => $this->now])->save();

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

        $config->set('auth.providers.integration_identities', [
            'driver' => 'model',
            'model'  => IntegrationIdentity::class,
        ]);

        $config->set('authentication.device.last_used_throttle_seconds', 60);
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
     * Persist a live device for the identity holding the stored rotation.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(IntegrationIdentity $identity): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return $device;
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
     * Sign a payload for this guard with the configured key, adding only the
     * timing, id and guard claims to the supplied ones.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encode(array $claims): string
    {
        $issuedAt = $this->now->getTimestamp();

        return JWT::encode([
            Claims::ISSUED_AT->value  => $issuedAt,
            Claims::EXPIRES_AT->value => $issuedAt + 600,
            Claims::JWT_ID->value     => 'token-id',
            Claims::GUARD->value      => self::GUARD,
            ...$claims,
        ], 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid');
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
