<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Queue\Worker;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Testing\Fakes\EventFake;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\GuardAuthenticationContexts;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Listeners\ForgetGuardStateBeforeJob;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMachineCredentials;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\MachineAccount;
use Tests\Integration\Fixtures\MachineMembership;
use Tests\Integration\Octane\Fixtures\AuthenticationReport;
use Tests\Integration\Octane\Fixtures\BindMembershipJob;
use Tests\Integration\Octane\Fixtures\ProbeContributor;
use Tests\Integration\Octane\Fixtures\ReportAuthenticationJob;
use Tests\Integration\Octane\Fixtures\RequestProbe;
use Tests\TestCase;

/**
 * Consecutive requests from different tenants, principals, guards and kinds of
 * credential, served by one Laravel Octane worker through its real lifecycle
 * (only Octane's own flushes and the package's), with a queued job run between
 * them: each request reports every guard's identity, principal, session, tenant
 * and scopes, the default guard, the caller, the authentication context (with a
 * contributor that depends on a scoped service) and the failures it reported,
 * and none of it is ever what an earlier request bound, whether that request
 * authenticated, threw, ended pending or was refused. The sequence runs in both
 * orders, so no assertion leans on what ran before it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(ApiKeyGuard::class)]
#[CoversClass(AuthManager::class)]
#[CoversClass(ForgetGuardStateBeforeJob::class)]
#[CoversClass(GuardAuthenticationContexts::class)]
final class CrossTenantRequestsTest extends TestCase
{
    use InteractsWithMachineCredentials, ServesRequestsThroughOctane;

    /** @var list<string> The guards every report resolves, in order: two applications for people, then two for machines. */
    private const array GUARDS = ['admin', 'console', 'machines', 'm2m'];

    /** @var string Plaintext password of every person. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var int People and machines seeded so far, numbering their emails and names. */
    private int $seeded = 0;

    /** @var int Reports asked for so far, numbering their request ids. */
    private int $requests = 0;

    /** @var ?string The request id of the report last asked for. */
    private ?string $requestId = null;

    /** @var ?array<string, mixed> What the request that throws reported, with its failures, just before it threw. */
    private ?array $exploded = null;

    /**
     * Freeze the clocks, create the tables, add the routes, register a
     * contributor whose scoped dependency the booted application resolves once,
     * as one that touches it at boot does, and boot the worker.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::freezeMachineClockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createMachineTables();
        $this->createPeopleTables();

        $this->registerSetUpRoutes();
        $this->registerReportRoutes();

        $this->app?->scoped(RequestProbe::class, static fn (Application $app): RequestProbe => new RequestProbe($app->make('request')->header('X-Request-Id')));
        $this->app?->make(ContextContributors::class)->register('probe', ProbeContributor::class);
        $this->app?->make(RequestProbe::class);

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
        foreach (['jobs', 'activatable_tenant_memberships', 'activatable_tenant_members'] as $table) {
            Schema::dropIfExists($table);
        }

        $this->dropMachineTables();

        self::releaseMachineClock();

        parent::tearDown();
    }

    /**
     * Rows of `[steps]`: the sequence in order and reversed.
     *
     * @return iterable<string, array{0: list<\Closure(self): void>}>
     */
    public static function provideOrders(): iterable
    {
        $steps = [
            static fn (self $test) => $test->aPersonInATenant(),
            static fn (self $test) => $test->anotherPersonInAnotherTenantOnAnotherGuard(),
            static fn (self $test) => $test->aPlatformPrincipal(),
            static fn (self $test) => $test->aSwitchToAnotherPrincipalInAnotherTenant(),
            static fn (self $test) => $test->aMachinesApiKey(),
            static fn (self $test) => $test->aClientCredentialsToken(),
            static fn (self $test) => $test->aRequestThatThrows(),
            static fn (self $test) => $test->aSignInThatEndsPending(),
            static fn (self $test) => $test->aQueuedJobBetweenRequests(),
            static fn (self $test) => $test->aGuest(),
        ];

        yield 'in order' => [$steps];
        yield 'reversed' => [array_reverse($steps)];
    }

    /**
     * Every step of the sequence, served by one worker, sees only what its own
     * request authenticated, in either order.
     *
     * @param  list<\Closure(self): void>  $steps
     * @return void
     */
    #[DataProvider('provideOrders')]
    public function testNothingOneRequestBindsReachesTheNext(array $steps): void
    {
        foreach ($steps as $step) {
            $step($this);
        }
    }

    /**
     * Configure the guards, the people's `admin` application the default, and a
     * database queue.
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

        self::configureMachineGuards($config);

        $config->set('auth.defaults.guard', 'admin');
        $config->set('auth.providers.people', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.admin', ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => ['password']]]);
        $config->set('auth.guards.console', ['driver' => 'jwt', 'provider' => 'people', 'application' => ['methods' => ['password']]]);
        $config->set('auth.guards.machines', ['driver' => 'api_key', 'provider' => 'accounts', 'application' => ['methods' => ['api_key']]]);
        $config->set('auth.guards.m2m', ['driver' => 'jwt', 'provider' => 'accounts', 'application' => ['methods' => ['client_credentials']]]);
        $config->set('queue.default', 'database');
        $config->set('queue.connections.database', ['driver' => 'database', 'table' => 'jobs', 'queue' => 'default', 'retry_after' => 90]);
    }

    /**
     * Person A, as membership P1 in tenant T1, on `admin` with a session token:
     * the other guards refuse the token as theirs, and nothing else is bound.
     *
     * @return void
     */
    private function aPersonInATenant(): void
    {
        [$tenant] = $this->tenants(1);

        [$person, [$membership]] = $this->seedPerson([$tenant]);

        $session = $this->signIn('admin', $person, $membership);

        $this->report($session['access'])->assertExactJson(self::expected(
            guards: ['admin' => self::bound($person, $membership, $session['session'], $tenant)],
            caller: self::caller('admin', 'access', $person, $membership, $tenant, $session['session']),
            context: $this->context('admin', $person, $membership, $tenant, $session['session'], 'access_token'),
            failures: [['console', 'token_invalid'], ['machines', 'credential_invalid'], ['m2m', 'token_invalid']],
        ));
    }

    /**
     * Person B, as P2 in T2, on `console`, the guard the request makes the
     * default: `admin` refuses the token, and nothing of any other person is
     * bound.
     *
     * @return void
     */
    private function anotherPersonInAnotherTenantOnAnotherGuard(): void
    {
        [$tenant] = $this->tenants(1);

        [$person, [$membership]] = $this->seedPerson([$tenant]);

        $session = $this->signIn('console', $person, $membership);

        $this->report($session['access'], 'console')->assertExactJson(self::expected(
            default: 'console',
            guards: ['console' => self::bound($person, $membership, $session['session'], $tenant)],
            caller: self::caller('console', 'access', $person, $membership, $tenant, $session['session']),
            context: $this->context('console', $person, $membership, $tenant, $session['session'], 'access_token'),
            failures: [['admin', 'token_invalid'], ['machines', 'credential_invalid'], ['m2m', 'token_invalid']],
        ));
    }

    /**
     * A platform principal, in no tenant, on `admin`: no tenant is bound, not
     * even one an earlier request bound.
     *
     * @return void
     */
    private function aPlatformPrincipal(): void
    {
        [$person, [$membership]] = $this->seedPerson([null]);

        $session = $this->signIn('admin', $person, $membership);

        $this->report($session['access'])->assertExactJson(self::expected(
            guards: ['admin' => self::bound($person, $membership, $session['session'], null)],
            caller: self::caller('admin', 'access', $person, $membership, null, $session['session']),
            context: $this->context('admin', $person, $membership, null, $session['session'], 'access_token'),
            failures: [['console', 'token_invalid'], ['machines', 'credential_invalid'], ['m2m', 'token_invalid']],
        ));
    }

    /**
     * A person signed in as P1 in T1 who switches to P3 in T3: the earlier
     * access token, naming T1, is refused as `session_tenant_mismatch` (the
     * session acts in T3 now), binding nothing, and the new one binds P3 in T3
     * in the same session.
     *
     * @return void
     */
    private function aSwitchToAnotherPrincipalInAnotherTenant(): void
    {
        [$first, $third] = $this->tenants(2);

        [$person, [$from, $to]] = $this->seedPerson([$first, $third]);

        $session  = $this->signIn('admin', $person, $from);
        $switched = $this->switchTo($session['refresh'], $to);

        $this->report($session['access'])->assertExactJson(self::expected(
            failures: [['admin', 'session_tenant_mismatch'], ['console', 'token_invalid'], ['machines', 'credential_invalid'], ['m2m', 'token_invalid']],
        ));

        $this->report($switched)->assertExactJson(self::expected(
            guards: ['admin' => self::bound($person, $to, $session['session'], $third)],
            caller: self::caller('admin', 'access', $person, $to, $third, $session['session']),
            context: $this->context('admin', $person, $to, $third, $session['session'], 'access_token'),
            failures: [['console', 'token_invalid'], ['machines', 'credential_invalid'], ['m2m', 'token_invalid']],
        ));
    }

    /**
     * Machine M's API key, as its membership in T4, on `machines`: the key's
     * scopes and tenant are bound there alone, and the `jwt` guards refuse the
     * key as a token.
     *
     * @return void
     */
    private function aMachinesApiKey(): void
    {
        [$account, $membership, $tenant] = $this->seedMachineAccount();

        $key = $this->issueKey('machines', $account, $membership, ['reports:read']);

        $this->report($key, 'machines')->assertExactJson(self::expected(
            default: 'machines',
            guards: ['machines' => self::bound($account, $membership, null, $tenant, ['reports:read'])],
            caller: self::caller('machines', 'access', $account, $membership, $tenant, null),
            context: $this->context('machines', $account, $membership, $tenant, null, 'api_key', ['reports:read']),
            failures: [['admin', 'token_invalid'], ['console', 'token_invalid'], ['m2m', 'token_invalid']],
        ));
    }

    /**
     * Machine N's client credentials token, as its membership in T5, on `m2m`:
     * the token's scopes and tenant are bound there alone, and the other guards
     * refuse it.
     *
     * @return void
     */
    private function aClientCredentialsToken(): void
    {
        [$account, $membership, $tenant] = $this->seedMachineAccount();

        $key   = $this->issueKey('m2m', $account, $membership, ['invoices:read', 'invoices:write']);
        $token = $this->exchange($key, 'invoices:read');

        $this->report($token, 'm2m')->assertExactJson(self::expected(
            default: 'm2m',
            guards: ['m2m' => self::bound($account, $membership, null, $tenant, ['invoices:read'])],
            caller: self::caller('m2m', 'access', $account, $membership, $tenant, null),
            context: $this->context('m2m', $account, $membership, $tenant, null, 'client_credentials', ['invoices:read']),
            failures: [['admin', 'token_invalid'], ['console', 'token_invalid'], ['machines', 'credential_invalid']],
        ));
    }

    /**
     * A person authenticated on a route that then throws: the route had the
     * person bound on `admin`, with the session, tenant and context, when it
     * threw the exception it throws, which became a server error, and the guest
     * request after it sees nothing of them.
     *
     * @return void
     */
    private function aRequestThatThrows(): void
    {
        [$tenant] = $this->tenants(1);

        [$person, [$membership]] = $this->seedPerson([$tenant]);

        $session = $this->signIn('admin', $person, $membership);

        $reported = [];

        Exceptions::reportable(static function (\Throwable $exception) use (&$reported): void {
            $reported[] = [$exception::class, $exception->getMessage()];
        });

        $this->requestId = 'request-' . ++$this->requests;
        $this->exploded  = null;

        $this->serve(self::octaneRequest('GET', '/explode', bearer: $session['access'], server: ['HTTP_X_REQUEST_ID' => $this->requestId]))->assertStatus(500);

        self::assertSame([[\RuntimeException::class, 'The route failed after authenticating.']], $reported);

        TestResponse::fromBaseResponse(new JsonResponse($this->exploded))->assertExactJson(self::expected(
            guards: ['admin' => self::bound($person, $membership, $session['session'], $tenant)],
            caller: self::caller('admin', 'access', $person, $membership, $tenant, $session['session']),
            context: $this->context('admin', $person, $membership, $tenant, $session['session'], 'access_token'),
            failures: [['console', 'token_invalid'], ['machines', 'credential_invalid'], ['m2m', 'token_invalid']],
        ));

        $this->report(null)->assertExactJson(self::expected());
    }

    /**
     * A sign-in that ends pending, waiting for a choice of principal: the next
     * request, carrying nothing, sees nothing; the one after, carrying the
     * pending credential on a route that declares it, has the pending session
     * as its caller and binds no guard.
     *
     * @return void
     */
    private function aSignInThatEndsPending(): void
    {
        $tenants = $this->tenants(2);

        [$person] = $this->seedPerson($tenants);

        $pending = $this->signIn('admin', $person, null);

        $this->report(null)->assertExactJson(self::expected());

        $request = self::octaneRequest('POST', '/pending-report', ['pending_credential' => $pending['pending_credential']]);

        $caller = ['guard' => 'admin', 'credential' => 'pending', 'identity' => $person->getKey(), 'principal' => null, 'tenant' => null];

        $this->serve($request)->assertOk()->assertExactJson(self::expected(caller: [...$caller, 'session' => $pending['pending'], 'pending' => $pending['pending']]));
    }

    /**
     * Queued jobs run, between a person's request and a guest's, on the
     * application that served them, its request one with no credential as a
     * queue worker's is: a job that binds a membership leaves the next job, and
     * the guest request after them, with every guard signed out.
     *
     * @return void
     */
    private function aQueuedJobBetweenRequests(): void
    {
        [$tenant] = $this->tenants(1);

        [$person, [$membership]] = $this->seedPerson([$tenant]);

        $session = $this->signIn('admin', $person, $membership);

        $this->report($session['access'])->assertJsonPath('guards.admin.identity', $person->getKey());

        $this->app?->instance('request', Request::create('/'));

        dispatch(new BindMembershipJob((int) $membership->getKey())); // @phpstan-ignore cast.int
        dispatch(new ReportAuthenticationJob(self::GUARDS));

        $worker = $this->app?->make('queue.worker');

        self::assertInstanceOf(Worker::class, $worker);

        $worker->runNextJob('database', 'default', new WorkerOptions(sleep: 0, maxTries: 1));

        self::assertSame($person->getKey(), Auth::manager()->guard('admin')->id());

        $worker->runNextJob('database', 'default', new WorkerOptions(sleep: 0, maxTries: 1));

        $expected = self::expected();

        unset($expected['failures']);

        self::assertSame($expected, $this->app?->make('observed.report'));

        $this->report(null)->assertExactJson(self::expected());
    }

    /**
     * A guest sees nothing.
     *
     * @return void
     */
    private function aGuest(): void
    {
        $this->report(null)->assertExactJson(self::expected());
    }

    /**
     * Register the routes that set the steps up: sign-in, switch, key issue and
     * token exchange.
     *
     * @return void
     */
    private function registerSetUpRoutes(): void
    {
        Route::post('/sign-in', static function (): array {
            $membership = request()->filled('principal') ? ChoosingMembership::query()->findOrFail(request()->integer('principal')) : null;
            $context    = SignInContext::fromRequest(request(), principal: $membership);
            $result     = Auth::sessions(request()->string('guard')->value())->signIn('password', request()->only('email', 'password'), $context);

            return [
                'access'             => $result->session?->tokens->accessToken->reveal(),
                'refresh'            => $result->session?->tokens->refreshToken?->reveal(),
                'session'            => $result->session?->record->getSessionIdentifier(),
                'pending'            => $result->pending?->id,
                'pending_credential' => $result->credential?->reveal(),
            ];
        });

        Route::post('/switch', static function (): array {
            $membership = ChoosingMembership::query()->findOrFail(request()->integer('principal'));
            $result     = Auth::sessions('admin')->switchTo(request()->string('refresh')->value(), SwitchTarget::principal($membership));

            return ['access' => $result->session?->tokens->accessToken->reveal()];
        });

        Route::post('/keys', static function (): array {
            $account    = MachineAccount::query()->findOrFail(request()->integer('account'));
            $membership = MachineMembership::query()->findOrFail(request()->integer('membership'));

            /** @var list<string> $scopes */
            $scopes = request()->array('scopes');

            return ['key' => Auth::apiKeys(request()->string('guard')->value())->issue($account, $membership, $scopes)->key()->reveal()];
        });

        Route::post('/oauth/token', static fn (): array => ['access' => Auth::clientCredentials('m2m')->fromRequest()->accessToken?->reveal()]);
    }

    /**
     * Register the routes the steps assert with: the report, the route that
     * throws once it has authenticated, and the pending report.
     *
     * @return void
     */
    private function registerReportRoutes(): void
    {
        Route::get('/report', function (): array {
            if (request()->filled('guard')) {
                Auth::shouldUse(request()->string('guard')->value());
            }

            return $this->reportWithFailures();
        });

        Route::get('/explode', function (): never {
            $this->exploded = $this->reportWithFailures();

            throw new \RuntimeException('The route failed after authenticating.');
        });

        Route::middleware('authentication.pending:choose_principal,admin')->post('/pending-report', fn (): array => $this->reportWithFailures());
    }

    /**
     * The report of the request being served, with the failures it reported
     * while it was made, each as its guard and reason.
     *
     * @return array<string, mixed>
     *
     * @throws \Throwable
     */
    private function reportWithFailures(): array
    {
        $fake = new EventFake(app(Dispatcher::class), [AuthenticationFailed::class]);

        app()->instance('events', $fake);

        $report   = AuthenticationReport::of(self::GUARDS);
        $failures = [];

        foreach ($fake->dispatched(AuthenticationFailed::class) as $arguments) {

            $failure = is_array($arguments) ? $arguments[0] ?? null : null;

            assert($failure instanceof AuthenticationFailed);

            $failures[] = [$failure->context->guard, $failure->reason->value];
        }

        return [...$report, 'failures' => $failures];
    }

    /**
     * Ask for the report with the bearer credential or none, making the guard
     * given the default for the request, under a request id of its own.
     *
     * @param  ?string  $bearer
     * @param  ?string  $guard
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function report(?string $bearer, ?string $guard = null): TestResponse
    {
        $this->requestId = 'request-' . ++$this->requests;

        $parameters = $guard === null ? [] : ['guard' => $guard];

        return $this->serve(self::octaneRequest('GET', '/report', $parameters, $bearer, server: ['HTTP_X_REQUEST_ID' => $this->requestId]))->assertOk();
    }

    /**
     * Sign the person in on the guard through the worker, as the membership
     * given or, with none, waiting for a choice.
     *
     * @param  string  $guard
     * @param  \Tests\Integration\Fixtures\ChoosingMember  $person
     * @param  ?\Tests\Integration\Fixtures\ChoosingMembership  $membership
     * @return array{access: ?string, refresh: ?string, session: mixed, pending: mixed, pending_credential: ?string}
     */
    private function signIn(string $guard, ChoosingMember $person, ?ChoosingMembership $membership): array
    {
        $parameters = ['guard' => $guard, 'email' => $person->email, 'password' => self::PASSWORD, ...($membership === null ? [] : ['principal' => $membership->getKey()])];

        $result = $this->serve(self::octaneRequest('POST', '/sign-in', $parameters))->assertOk()->json();

        self::assertIsArray($result);

        /** @var array{access: ?string, refresh: ?string, session: mixed, pending: mixed, pending_credential: ?string} $result */
        return $result;
    }

    /**
     * Switch the session the refresh token belongs to to the membership,
     * through the worker, returning the new access token.
     *
     * @param  ?string  $refresh
     * @param  \Tests\Integration\Fixtures\ChoosingMembership  $membership
     * @return string
     */
    private function switchTo(?string $refresh, ChoosingMembership $membership): string
    {
        $access = $this->serve(self::octaneRequest('POST', '/switch', ['refresh' => $refresh, 'principal' => $membership->getKey()]))->assertOk()->json('access');

        self::assertIsString($access);

        return $access;
    }

    /**
     * Issue a key on the guard for the account as the membership, through the
     * worker.
     *
     * @param  string  $guard
     * @param  \Tests\Integration\Fixtures\MachineAccount  $account
     * @param  \Tests\Integration\Fixtures\MachineMembership  $membership
     * @param  list<string>  $scopes
     * @return string
     */
    private function issueKey(string $guard, MachineAccount $account, MachineMembership $membership, array $scopes): string
    {
        $parameters = ['guard' => $guard, 'account' => $account->getKey(), 'membership' => $membership->getKey(), 'scopes' => $scopes];
        $key        = $this->serve(self::octaneRequest('POST', '/keys', $parameters))->assertOk()->json('key');

        self::assertIsString($key);

        return $key;
    }

    /**
     * Exchange the `m2m` key for an access token granting the scope, through
     * the worker, the client authenticated with HTTP Basic.
     *
     * @param  string  $key
     * @param  string  $scope
     * @return string
     */
    private function exchange(string $key, string $scope): string
    {
        $separator = strrpos($key, '_');

        self::assertIsInt($separator);

        $basic  = ['HTTP_AUTHORIZATION' => 'Basic ' . base64_encode(substr($key, 0, $separator) . ':' . substr($key, $separator + 1))];
        $access = $this->serve(self::octaneRequest('POST', '/oauth/token', ['grant_type' => 'client_credentials', 'scope' => $scope], server: $basic))->json('access');

        self::assertIsString($access);

        return $access;
    }

    /**
     * Create the people and membership tables, a membership's tenant optional
     * so a platform principal acts in none, and the jobs table.
     *
     * @return void
     */
    private function createPeopleTables(): void
    {
        Schema::create('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id')->nullable();
            $blueprint->timestamps();
        });

        Schema::create('jobs', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('queue')->index();
            $blueprint->longText('payload');
            $blueprint->unsignedTinyInteger('attempts');
            $blueprint->unsignedInteger('reserved_at')->nullable();
            $blueprint->unsignedInteger('available_at');
            $blueprint->unsignedInteger('created_at');
        });
    }

    /**
     * Persist the number of active tenants.
     *
     * @param  int  $count
     * @return list<\Tests\Integration\Fixtures\ActivatableTenant>
     */
    private function tenants(int $count): array
    {
        $tenants = [];

        for ($index = 0; $index < $count; $index++) {
            $tenants[] = ActivatableTenant::query()->create(['name' => 'Tenant ' . ++$this->seeded, 'is_active' => true]);
        }

        return $tenants;
    }

    /**
     * Persist a person with one membership in each tenant given, `null` for a
     * platform membership in none.
     *
     * @param  list<?\Tests\Integration\Fixtures\ActivatableTenant>  $tenants
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: list<\Tests\Integration\Fixtures\ChoosingMembership>}
     */
    private function seedPerson(array $tenants): array
    {
        $person      = ChoosingMember::query()->create(['email' => 'person' . ++$this->seeded . '@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach ($tenants as $tenant) {
            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $person->getKey(), 'tenant_id' => $tenant?->getKey()]);
        }

        return [$person, $memberships];
    }

    /**
     * Persist a service account with one membership of a tenant of its own.
     *
     * @return array{0: \Tests\Integration\Fixtures\MachineAccount, 1: \Tests\Integration\Fixtures\MachineMembership, 2: \Tests\Integration\Fixtures\ActivatableTenant}
     */
    private function seedMachineAccount(): array
    {
        [$tenant] = $this->tenants(1);

        return $this->seedAccount($tenant);
    }

    /**
     * What the report of a request says: the default guard, every guard a guest
     * but those given, the caller, the authentication context, and the failures
     * reported.
     *
     * @param  string  $default
     * @param  array<string, array<string, mixed>>  $guards
     * @param  ?array<string, mixed>  $caller
     * @param  ?array<string, mixed>  $context
     * @param  list<array{0: string, 1: string}>  $failures
     * @return array<string, mixed>
     */
    private static function expected(string $default = 'admin', array $guards = [], ?array $caller = null, ?array $context = null, array $failures = []): array
    {
        $everyGuard = array_fill_keys(self::GUARDS, AuthenticationReport::guest());

        return ['default' => $default, 'guards' => [...$everyGuard, ...$guards], 'caller' => $caller, 'context' => $context, 'failures' => $failures];
    }

    /**
     * The authentication context the report just served says the request has:
     * the package's keys for the credential, and the probe's, naming that
     * request.
     *
     * @param  string  $application
     * @param  \Tests\Integration\Fixtures\ChoosingMember|\Tests\Integration\Fixtures\MachineAccount  $identity
     * @param  \Tests\Integration\Fixtures\ChoosingMembership|\Tests\Integration\Fixtures\MachineMembership  $principal
     * @param  ?\Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @param  mixed  $session
     * @param  string  $credential
     * @param  ?list<string>  $scopes
     * @return array<string, array<string, mixed>>
     */
    private function context(
        string $application,
        ChoosingMember|MachineAccount $identity,
        ChoosingMembership|MachineMembership $principal,
        ?ActivatableTenant $tenant,
        mixed $session,
        string $credential,
        ?array $scopes = null,
    ): array {
        $person = $identity instanceof ChoosingMember;

        return [
            'authentication' => [
                'subject_type'          => $person ? 'person' : 'machine',
                'identity_type'         => $identity::class,
                'identity_id'           => IdentifierCoercion::stringify($identity->getKey()),
                'principal_type'        => $principal::class,
                'principal_id'          => IdentifierCoercion::stringify($principal->getKey()),
                'tenant_type'           => $tenant === null ? null : ActivatableTenant::class,
                'tenant_id'             => IdentifierCoercion::stringify($tenant?->getKey()),
                'application'           => $application,
                'session_id'            => $session,
                'amr'                   => $person ? ['pwd'] : [],
                'auth_time'             => $person ? CarbonImmutable::now()->getTimestamp() : null,
                'mfa'                   => false,
                'recovery_code'         => false,
                'multifactor'           => false,
                'seconds_since_step_up' => null,
                'credential'            => $credential,
                'scopes'                => $scopes,
                'ip'                    => '203.0.113.7',
            ],
            'probe' => ['request_id' => $this->requestId, 'application' => $application],
        ];
    }

    /**
     * What a guard reports bound: the identity, principal, session and tenant
     * identifiers, and the scopes.
     *
     * @param  \Tests\Integration\Fixtures\ChoosingMember|\Tests\Integration\Fixtures\MachineAccount  $identity
     * @param  \Tests\Integration\Fixtures\ChoosingMembership|\Tests\Integration\Fixtures\MachineMembership  $principal
     * @param  mixed  $session
     * @param  ?\Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @param  ?list<string>  $scopes
     * @return array<string, mixed>
     */
    private static function bound(
        ChoosingMember|MachineAccount $identity,
        ChoosingMembership|MachineMembership $principal,
        mixed $session,
        ?ActivatableTenant $tenant,
        ?array $scopes = null,
    ): array {
        return ['identity' => $identity->getKey(), 'principal' => $principal->getKey(), 'session' => $session, 'tenant' => $tenant?->getKey(), 'scopes' => $scopes];
    }

    /**
     * What the report says of the caller.
     *
     * @param  string  $guard
     * @param  string  $credential
     * @param  \Tests\Integration\Fixtures\ChoosingMember|\Tests\Integration\Fixtures\MachineAccount  $identity
     * @param  \Tests\Integration\Fixtures\ChoosingMembership|\Tests\Integration\Fixtures\MachineMembership  $principal
     * @param  ?\Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @param  mixed  $session
     * @return array<string, mixed>
     */
    private static function caller(
        string $guard,
        string $credential,
        ChoosingMember|MachineAccount $identity,
        ChoosingMembership|MachineMembership $principal,
        ?ActivatableTenant $tenant,
        mixed $session,
    ): array {
        return [
            'guard'      => $guard,
            'credential' => $credential,
            'identity'   => $identity->getKey(),
            'principal'  => $principal->getKey(),
            'tenant'     => $tenant?->getKey(),
            'session'    => $session,
            'pending'    => null,
        ];
    }
}
