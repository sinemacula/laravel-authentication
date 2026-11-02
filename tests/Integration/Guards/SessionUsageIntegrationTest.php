<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Listeners\RecordSessionUsage;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * End-to-end tests for recording a session's last use: bearer requests through
 * the `auth` middleware and refresh both record when, from which IP address,
 * and with which user agent the session was used, on the shipped table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecordSessionUsage::class)]
#[CoversClass(ClientContext::class)]
final class SessionUsageIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string Plaintext rotation id stored on the seeded session. */
    private const string ROTATION_ID = 'stored-rotation-id';

    /** @var string Timestamp format of the stored columns. */
    private const string DATETIME_FORMAT = 'Y-m-d H:i:s';

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /**
     * Freeze the clock, create the identity table, and register a route behind
     * the `auth` middleware that reports the bound session.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Route::middleware('auth:api')->get('/session', static fn (): array => Auth::session() instanceof Session ? Auth::session()->toArray() : []);
    }

    /**
     * Release the frozen clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A bearer request records the time, the client's IP address, and its user
     * agent on the session it authenticates with.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRequestRecordsTheClientItCameFrom(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $this->bearerRequest($identity, $session, '203.0.113.7', 'Client/1.0')->assertOk();

        self::assertSame(
            [$this->now->format(self::DATETIME_FORMAT), '203.0.113.7', 'Client/1.0'],
            $this->storedUsage($session),
        );
    }

    /**
     * Two requests served by the same application instance, as a long-running
     * worker serves them, each record their own client once the throttle window
     * has passed, and a request inside the window records nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachRequestRecordsItsOwnClientOutsideTheThrottleWindow(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $this->bearerRequest($identity, $session, '203.0.113.7', 'Phone/1.0')->assertOk();

        $this->moveClockTo($this->now->copy()->addSeconds(30));

        $this->bearerRequest($identity, $session, '198.51.100.1', 'Inside/1.0')->assertOk();

        self::assertSame([$this->now->format(self::DATETIME_FORMAT), '203.0.113.7', 'Phone/1.0'], $this->storedUsage($session));

        $later = $this->now->copy()->addMinutes(2);

        $this->moveClockTo($later);

        $this->bearerRequest($identity, $session, '2001:db8::1', 'Laptop/2.0')->assertOk();

        self::assertSame([$later->format(self::DATETIME_FORMAT), '2001:db8::1', 'Laptop/2.0'], $this->storedUsage($session));
    }

    /**
     * A request that sends no `User-Agent` header, once the throttle window has
     * passed, records its IP address and no user agent in place of the one an
     * earlier request recorded: the stored client is the client of that use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRequestWithoutAUserAgentRecordsNoneInPlaceOfTheEarlierOne(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $this->bearerRequest($identity, $session, '203.0.113.7', 'Phone/1.0')->assertOk();

        $later = $this->now->copy()->addMinutes(2);

        $this->moveClockTo($later);

        $request = Request::create('/session', 'GET', server: [
            'REMOTE_ADDR'        => '198.51.100.1',
            'HTTP_AUTHORIZATION' => 'Bearer ' . $this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal(),
        ]);

        $request->server->remove('HTTP_USER_AGENT');
        $request->headers->remove('User-Agent');

        self::assertSame(200, app(HttpKernel::class)->handle($request)->getStatusCode());
        self::assertSame([$later->format(self::DATETIME_FORMAT), '198.51.100.1', null], $this->storedUsage($session));
    }

    /**
     * A refresh records the client of the refresh request on the session it
     * rotated.
     *
     * @return void
     */
    public function testRefreshRecordsTheClientItCameFrom(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        Route::post('/refresh', function (): array {
            $tokens = GuardSessions::of($this->guard())->refresh(request()->string('refresh_token')->toString())->session?->tokens;

            return ['refreshed' => $tokens !== null];
        });

        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])
            ->withHeaders(['User-Agent' => 'Refresher/3.1'])
            ->postJson('/refresh', ['refresh_token' => $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal()])
            ->assertOk()
            ->assertExactJson(['refreshed' => true]);

        self::assertSame([$this->now->format(self::DATETIME_FORMAT), '192.0.2.10', 'Refresher/3.1'], $this->storedUsage($session));
    }

    /**
     * A bearer request and a refresh record their client on the session they
     * used and on no other: another session of the same identity and a session
     * of another identity keep their own last use.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRecordsTheClientOnlyOnTheSessionThatWasUsed(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();
        [$stranger]           = $this->seedIdentityWithSession('stranger@example.test');

        $earlier = $this->now->copy()->subDay();
        $others  = [
            $this->seedSession($identity, ['last_used_at' => $earlier, 'last_used_ip' => '198.51.100.9', 'last_used_user_agent' => 'Sibling/1.0']),
            $this->seedSession($stranger, ['last_used_at' => $earlier, 'last_used_ip' => '198.51.100.10', 'last_used_user_agent' => 'Stranger/1.0']),
        ];

        $before = array_map($this->storedUsage(...), $others);

        Route::post('/refresh', fn (): array => ['refreshed' => GuardSessions::of($this->guard())->refresh(request()->string('refresh_token')->toString())->isRefreshed()]);

        $this->bearerRequest($identity, $session, '203.0.113.7', 'Client/1.0')->assertOk();

        self::assertSame([$this->now->format(self::DATETIME_FORMAT), '203.0.113.7', 'Client/1.0'], $this->storedUsage($session));
        self::assertSame($before, array_map($this->storedUsage(...), $others));

        $this->moveClockTo($this->now->copy()->addMinutes(2));

        $this->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])
            ->withHeaders(['User-Agent' => 'Refresher/3.1'])
            ->postJson('/refresh', ['refresh_token' => $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal()])
            ->assertExactJson(['refreshed' => true]);

        self::assertSame('192.0.2.10', $this->storedUsage($session)[1]);
        self::assertSame($before, array_map($this->storedUsage(...), $others));
    }

    /**
     * A session created as the guides show records the guard, the principal,
     * and the client it was created from, with the client's IP address and user
     * agent cleaned by `ClientContext` so a crafted header is stored rather
     * than failing the insert, and the tokens issued for it then work on the
     * bearer path and on refresh.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testSessionCreatedAsDocumentedRecordsWhereItWasCreated(): void
    {
        [$identity] = $this->seedIdentityWithSession();

        $this->routeDocumentedSignIn($identity);

        $response = $this->withServerVariables(['REMOTE_ADDR' => '2001:db8::7'])
            ->withHeaders(['User-Agent' => "Crafted\0/1.0 \xC3\x28" . str_repeat('x', 600)])
            ->postJson('/sign-in', ['client_name' => 'Work laptop', 'platform' => 'macOS'])
            ->assertOk();

        $row = (array) DB::table('authentication_sessions')->where('id', $response->json('session'))->first();

        self::assertSame('api', $row['guard']);
        self::assertSame(StubPrincipal::class, $row['principal_type']);
        self::assertSame((string) $identity->getKey(), $row['principal_id']); // @phpstan-ignore cast.string
        self::assertSame(['Work laptop', 'macOS', '2001:db8::7'], [$row['client_name'], $row['platform'], $row['created_ip']]);
        self::assertIsString($row['created_user_agent']);
        self::assertStringStartsWith('Crafted/1.0 ?(', $row['created_user_agent']);
        self::assertSame(512, mb_strlen($row['created_user_agent'], 'UTF-8'));

        $access  = $response->json('access_token');
        $refresh = $response->json('refresh_token');

        self::assertIsString($access);
        self::assertIsString($refresh);

        $this->withHeaders(['Authorization' => 'Bearer ' . $access])->getJson('/session')->assertOk()->assertJsonPath('id', $response->json('session'));

        self::assertNotNull(GuardSessions::of($this->guard())->refresh($refresh)->session);
    }

    /**
     * Rows of `[sign-in input]`: client names and platforms the documented
     * validation rejects, each of which would otherwise fail the request or be
     * stored cut short on some engine.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideUnsafeClientMetadata(): iterable
    {
        yield from [
            'name with a NUL byte'          => [['client_name' => "Work\0laptop"]],
            'platform with invalid UTF-8'   => [['platform' => "mac\xFFOS"]],
            'name over 255 characters'      => [['client_name' => str_repeat('é', 256)]],
            'platform that is not a string' => [['platform' => ['macOS']]],
        ];
    }

    /**
     * The documented sign-in validates the client name and platform before
     * storing them, so a client sending one that cannot be stored gets a
     * validation error instead of a server error, and no session is created.
     *
     * @param  array<string, mixed>  $input
     * @return void
     */
    #[DataProvider('provideUnsafeClientMetadata')]
    public function testSessionCreatedAsDocumentedRejectsClientMetadataThatCannotBeStored(array $input): void
    {
        [$identity] = $this->seedIdentityWithSession();

        $this->routeDocumentedSignIn($identity);

        $this->post('/sign-in', $input, ['Accept' => 'application/json'])
            ->assertUnprocessable()
            ->assertJsonValidationErrors(array_keys($input));

        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * A client name and platform of exactly 255 characters, multibyte ones
     * included, pass the documented validation and are stored whole on every
     * engine.
     *
     * @return void
     */
    public function testSessionCreatedAsDocumentedStoresClientMetadataUpTo255Characters(): void
    {
        [$identity] = $this->seedIdentityWithSession();

        $this->routeDocumentedSignIn($identity);

        $name     = str_repeat('é', 255);
        $platform = str_repeat('日', 255);
        $session  = $this->postJson('/sign-in', ['client_name' => $name, 'platform' => $platform])->assertOk()->json('session');

        self::assertSame([$name, $platform], array_values((array) DB::table('authentication_sessions')->where('id', $session)->first(['client_name', 'platform'])));
    }

    /**
     * A user agent with a NUL byte and invalid UTF-8 is stored cleaned on every
     * engine, instead of failing the request (invalid UTF-8) or being cut short
     * at the NUL byte (PostgreSQL).
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testCraftedUserAgentIsStoredCleaned(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        $this->bearerRequest($identity, $session, '203.0.113.7', "Crafted\0/1.0 \xC3\x28" . str_repeat('x', 600))->assertOk();

        $stored = $this->storedUsage($session)[2];

        self::assertIsString($stored);
        self::assertStringStartsWith('Crafted/1.0 ?(', $stored);
        self::assertSame(512, mb_strlen($stored, 'UTF-8'));
    }

    /**
     * The session a request binds serialises without either refresh digest.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBoundSessionSerializesWithoutItsDigests(): void
    {
        [$identity, $session] = $this->seedIdentityWithSession();

        DB::table('authentication_sessions')->where('id', $session->getKey())->update(['previous_refresh_key' => RefreshTokenHasher::hash('older-rotation-id')]);

        $this->bearerRequest($identity, $session, '203.0.113.7', 'Client/1.0')
            ->assertOk()
            ->assertJsonPath('id', $session->getKey())
            ->assertJsonMissingPath('refresh_key')
            ->assertJsonMissingPath('previous_refresh_key');
    }

    /**
     * Configure the `api` guard over the identity table.
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
            'driver'      => 'jwt',
            'provider'    => 'identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('authentication.session.last_used_throttle_seconds', 60);
    }

    /**
     * Register a `/sign-in` route that creates a session for the identity and
     * issues its tokens exactly as the guides show.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @return void
     */
    private function routeDocumentedSignIn(StubPrincipal $identity): void
    {
        Route::post('/sign-in', function () use ($identity): array {
            $tokens    = $this->tokens();
            $lifetimes = $tokens->lifetimes();
            $absolute  = $lifetimes->absoluteDeadline(Carbon::now());
            $rotation  = RefreshTokenHasher::generate();
            $client    = ClientContext::fromRequest(request());
            $described = request()->validate([ // @phpstan-ignore staticMethod.dynamicCall
                'client_name' => ['nullable', 'string', 'max:255', 'regex:/^[^\x00]*$/u'],
                'platform'    => ['nullable', 'string', 'max:255', 'regex:/^[^\x00]*$/u'],
            ]);

            $session = new Session($described);
            $session->forceFill([
                'authenticatable_type' => $identity->getMorphClass(),
                'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
                'principal_type'       => $identity->getMorphClass(),
                'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
                'guard'                => 'api',
                'status'               => 'active',
                'tenant_id'            => null,
                'switched_at'          => null,
                'sign_in_method'       => 'password',
                'created_ip'           => $client->ip,
                'created_user_agent'   => $client->userAgent,
                'refresh_key'          => RefreshTokenHasher::hash($rotation),
                'signed_in_at'         => Carbon::now(),
                'idle_expires_at'      => $lifetimes->idleDeadline(Carbon::now(), $absolute),
                'absolute_expires_at'  => $absolute,
            ])->save();

            return [
                'session'       => $session->getKey(),
                'access_token'  => $tokens->issueAccessToken($identity, $identity, null, $session)->reveal(),
                'refresh_token' => $tokens->issueRefreshToken($session, $rotation, $identity)->reveal(),
            ];
        });
    }

    /**
     * Send a request to the session route with an access token for the session,
     * from the given client.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  string  $ip
     * @param  string  $userAgent
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     *
     * @throws \Random\RandomException
     */
    private function bearerRequest(StubPrincipal $identity, Session $session, string $ip, string $userAgent): TestResponse
    {
        $token = $this->tokens()->issueAccessToken($identity, $identity, null, $session)->reveal();

        return $this->withServerVariables(['REMOTE_ADDR' => $ip])
            ->withHeaders(['Authorization' => 'Bearer ' . $token, 'User-Agent' => $userAgent])
            ->getJson('/session');
    }

    /**
     * Move the application and JWT clocks to the given time.
     *
     * @param  \Carbon\Carbon  $at
     * @return void
     */
    private function moveClockTo(Carbon $at): void
    {
        Carbon::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }

    /**
     * Persist an identity with one live session holding the stored rotation.
     *
     * @param  string  $email
     * @return array{0: \Tests\Unit\Stubs\StubPrincipal, 1: \SineMacula\Laravel\Authentication\Models\Session}
     */
    private function seedIdentityWithSession(string $email = 'session-usage@example.test'): array
    {
        $identity            = new StubPrincipal;
        $identity->email     = $email;
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        return [$identity, $this->seedSession($identity, ['refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID)])];
    }

    /**
     * Persist a live session of the identity with any further state.
     *
     * @param  \Tests\Unit\Stubs\StubPrincipal  $identity
     * @param  array<string, mixed>  $state
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(StubPrincipal $identity, array $state): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            ...$state,
        ])->save();

        return $session;
    }

    /**
     * Read the stored last-use time, IP address, and user agent of a session.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return list<mixed>
     */
    private function storedUsage(Session $session): array
    {
        $row = DB::table('authentication_sessions')->where('id', $session->getKey())->first(['last_used_at', 'last_used_ip', 'last_used_user_agent']);

        self::assertNotNull($row);

        $lastUsedAt = $row->last_used_at === null ? null : Carbon::parse($row->last_used_at)->format(self::DATETIME_FORMAT); // @phpstan-ignore argument.type

        return [$lastUsedAt, $row->last_used_ip, $row->last_used_user_agent];
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * The `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $guard = $manager->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
