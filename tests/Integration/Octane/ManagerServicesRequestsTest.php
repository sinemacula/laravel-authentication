<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\Fixtures\Sessions\ProvenIdentitySignIn;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * End-to-end tests for the auth manager's services served by one Laravel Octane
 * worker. The worker shares one auth manager between requests, and Octane hands
 * it each request's sandbox, so `Auth::sessions()`, `Auth::jwt()` and
 * `Auth::codes()` act on the request being served: its client, its
 * configuration and the dispatcher bound in it, never those of the application
 * the worker booted or of an earlier request. A sign-in method registered at
 * boot, as a service provider registers one, is built with each request's
 * sandbox too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthManager::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(CodeService::class)]
#[CoversClass(JwtTokenServiceFactory::class)]
#[CoversClass(SignInMethodManager::class)]
final class ManagerServicesRequestsTest extends TestCase
{
    use InteractsWithCodeIdentities, ServesRequestsThroughOctane;

    /** @var list<class-string<\SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent>> The session lifecycle events each request records. */
    private const array LIFECYCLE = [SignedIn::class, Refreshed::class, PrincipalSwitched::class, DeviceRevoked::class];

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var list<\Illuminate\Contracts\Foundation\Application> The applications the sign-in method registered at boot was built with. */
    private array $builtWith = [];

    /** @var list<\Illuminate\Contracts\Foundation\Application> The applications that served a sign-in with that method. */
    private array $servedBy = [];

    /** @var list<\SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender> The sender each request that sent a code bound. */
    private array $senders = [];

    /**
     * Freeze the clocks, create the tables, register a sign-in method at boot,
     * add the routes and boot the worker.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE]);

        $built = &$this->builtWith;

        $this->app?->make(SignInMethodManager::class)->extend('trusted', function (Application $app) use (&$built): ProvenIdentitySignIn {
            $built[] = $app;

            return new ProvenIdentitySignIn;
        });

        $this->addServiceRoutes();
        $this->bootOctaneWorker();
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A sign-in, a refresh, a switch of principal and a sign-out, each in a
     * request of its own from its own address, through a guard resolved before
     * the request bound a dispatcher of its own: each reports through its own
     * request's dispatcher, with its own client, and only its own events, none
     * reaching an earlier request's; the session ends signed out, and its last
     * token is refused.
     *
     * @return void
     */
    public function testASessionLifecycleActsThroughEachRequestsSandbox(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        $signIn = $this->serve(self::octaneRequest('POST', '/members/sign-in', self::credentials('member@example.test'), ip: '203.0.113.1'));

        $signIn->assertJson(['principal' => $first->getKey()]);

        $refresh = $this->serve(self::octaneRequest('POST', '/members/refresh', ['refresh' => $signIn->json('refresh')], ip: '203.0.113.2'));

        $switch = $this->serve(self::octaneRequest('POST', '/members/switch', ['refresh' => $refresh->json('refresh'), 'membership' => $second->getKey()], ip: '203.0.113.3'));

        $switch->assertJson(['principal' => $second->getKey()]);

        $access = $switch->json('access');

        self::assertIsString($access);

        $signOut = $this->serve(self::octaneRequest('POST', '/members/sign-out', bearer: $access, ip: '203.0.113.4'));

        $signOut->assertExactJson(['signed_out' => true]);

        $this->serve(self::octaneRequest('GET', '/members/me', bearer: $access))->assertExactJson(['principal' => null]);

        self::assertSame(['203.0.113.1', 'signed_out'], [DB::table('devices')->value('created_ip'), DB::table('devices')->value('revoked_reason')]);
        self::assertSame([
            [['SignedIn', '203.0.113.1']],
            [['SignedIn', '203.0.113.2'], ['Refreshed', '203.0.113.2']],
            [['PrincipalSwitched', '203.0.113.3']],
            [['DeviceRevoked', '203.0.113.4']],
        ], $this->eventsRecordedByEachRequest());
    }

    /**
     * A token lifetime changed in one request's configuration applies to that
     * request alone: `Auth::jwt()` and the session it signs in use it, the next
     * request is back to the configured lifetime, and the booted application's
     * configuration never changed.
     *
     * @return void
     */
    public function testAConfigurationChangedInOneRequestStaysInIt(): void
    {
        $this->seedIdentity();

        $this->serve(self::octaneRequest('POST', '/api/sign-in', [...self::credentials(), 'ttl' => 5]))->assertExactJson(['minutes' => 5, 'seconds' => 300]);
        $this->serve(self::octaneRequest('POST', '/api/sign-in', self::credentials()))->assertExactJson(['minutes' => 15, 'seconds' => 900]);

        self::assertSame(15, config('authentication.jwt.access_ttl_minutes'));
    }

    /**
     * A sign-in method registered on the manager at boot is built with the
     * sandbox of each request that signs in with it, never with the booted
     * application, so it resolves what it needs from the request being served.
     *
     * @return void
     */
    public function testAMethodRegisteredAtBootIsBuiltWithEachRequestsSandbox(): void
    {
        $this->seedIdentity();

        $this->serve(self::octaneRequest('POST', '/api/trusted', ['email' => 'ada@example.test']))->assertExactJson(['signed_in' => true]);
        $this->serve(self::octaneRequest('POST', '/api/trusted', ['email' => 'ada@example.test']))->assertExactJson(['signed_in' => true]);

        self::assertCount(2, $this->servedBy);
        self::assertSame($this->servedBy, $this->builtWith);
        self::assertNotSame($this->servedBy[0], $this->servedBy[1]);
        self::assertNotContains($this->app, $this->builtWith);
    }

    /**
     * The password method, built by a manager resolved at boot, reads the
     * configuration of the request it signs in: a request that turns the rehash
     * on sign-in off keeps the outdated hash, and the next request, with the
     * setting as configured, upgrades it.
     *
     * @return void
     */
    public function testThePasswordMethodReadsEachRequestsConfiguration(): void
    {
        $this->seedIdentity();

        $outdated = password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 5]);

        DB::table('integration_identities')->update(['password' => $outdated]);

        $this->serve(self::octaneRequest('POST', '/api/sign-in', [...self::credentials(), 'rehash' => false]))->assertOk();

        self::assertSame($outdated, DB::table('integration_identities')->value('password'));

        $this->serve(self::octaneRequest('POST', '/api/sign-in', self::credentials()))->assertOk();

        self::assertNotSame($outdated, DB::table('integration_identities')->value('password'));
    }

    /**
     * A code sent through `Auth::codes()` in one request is delivered once its
     * response is sent, through the sender bound in that request's sandbox, and
     * signs in on the next request, which reports through its own dispatcher.
     *
     * @return void
     */
    public function testACodeSentInOneRequestSignsInOnTheNext(): void
    {
        self::seedCodeIdentity();

        $this->serve(self::octaneRequest('POST', '/codes/send', ['phone' => self::PHONE]))->assertExactJson(['sent' => true]);

        self::assertCount(1, $this->senders);
        self::assertSame(self::CODE, $this->senders[0]->lastCodeFor(self::PHONE));

        $this->serve(self::octaneRequest('POST', '/codes/sign-in', ['phone' => self::PHONE, 'code' => self::CODE], ip: '203.0.113.9'))
            ->assertExactJson(['signed_in' => true]);

        self::assertSame([[['SignedIn', '203.0.113.9']]], $this->eventsRecordedByEachRequest());
    }

    /**
     * Configure the guards.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configureCodeGuards($config);
    }

    /**
     * Add the routes: each resolves the guard it acts through before it binds a
     * dispatcher of its own, as a route behind authentication middleware would.
     *
     * @return void
     */
    private function addServiceRoutes(): void
    {
        Route::post('/members/sign-in', function (): array {
            $sessions = Auth::sessions('members');
            $this->recordInThisRequest(self::LIFECYCLE);
            $session = $sessions->signIn('password', request()->only('email', 'password'))->session;

            return [
                'principal' => $session?->principal->getPrincipalIdentifier(),
                'refresh'   => $session?->tokens->refreshToken,
            ];
        });

        Route::post('/members/refresh', function (): array {
            $guard = Auth::manager()->guard('members');

            self::assertInstanceOf(JwtGuard::class, $guard);

            $this->recordInThisRequest(self::LIFECYCLE);
            $pair = $guard->refresh(request()->string('refresh')->value());

            return ['refresh' => $pair?->refreshToken];
        });

        Route::post('/members/switch', function (): array {
            $sessions = Auth::sessions('members');
            $this->recordInThisRequest(self::LIFECYCLE);
            $target = ActivatableTenantMembership::query()->findOrFail(request()->integer('membership'));
            $result = $sessions->switchPrincipal(request()->string('refresh')->value(), $target);

            return [
                'principal' => $result->session?->principal->getPrincipalIdentifier(),
                'access'    => $result->session?->tokens->accessToken,
            ];
        });

        Route::post('/members/sign-out', function (): array {
            $sessions = Auth::sessions('members');
            $this->recordInThisRequest(self::LIFECYCLE);

            return ['signed_out' => $sessions->signOut()];
        });

        Route::get('/members/me', static fn (): array => ['principal' => self::contextOf('members')['principal']]);

        Route::post('/api/sign-in', static function (): array {
            if (request()->has('ttl')) {
                config(['authentication.jwt.access_ttl_minutes' => request()->integer('ttl')]);
            }

            if (request()->has('rehash')) {
                config(['hashing.rehash_on_login' => request()->boolean('rehash')]);
            }

            $minutes = Auth::jwt('api')->lifetimes()->accessTtlMinutes;
            $access  = Auth::sessions('api')->signIn('password', request()->only('email', 'password'))->session?->tokens->accessToken;
            $claims  = $access === null ? null : Auth::jwt('api')->parse($access);

            self::assertIsArray($claims);
            self::assertIsInt($claims[Claims::EXPIRES_AT->value]);
            self::assertIsInt($claims[Claims::ISSUED_AT->value]);

            return ['minutes' => $minutes, 'seconds' => $claims[Claims::EXPIRES_AT->value] - $claims[Claims::ISSUED_AT->value]];
        });

        Route::post('/api/trusted', function (): array {
            $this->servedBy[] = app();

            return ['signed_in' => Auth::sessions('api')->signIn('trusted', request()->only('email'))->isSignedIn()];
        });

        Route::post('/codes/send', function (): array {
            $this->senders[] = FakeOneTimeCodeSender::fake();

            return ['sent' => Auth::codes('mobile')->send('phone_code', request()->only('phone'))->isSent()];
        });

        Route::post('/codes/sign-in', function (): array {
            $sessions = Auth::sessions('mobile');
            $this->recordInThisRequest(self::LIFECYCLE);

            return ['signed_in' => $sessions->signIn('phone_code', request()->only('phone', 'code'))->isSignedIn()];
        });
    }
}
