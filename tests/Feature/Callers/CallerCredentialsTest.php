<?php

declare(strict_types = 1);

namespace Tests\Feature\Callers;

use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\CallerCredentials;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithCallers;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of how a request's caller is read from the credential its route
 * declares.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CallerCredentials::class)]
final class CallerCredentialsTest extends TestCase
{
    use InteractsWithCallers, InteractsWithMachineClients;

    /** @var string A cookie application over the same members. */
    private const string BROWSER = 'browser';

    /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Events\AuthenticationFailed> The failures reported since the test began. */
    private \ArrayObject $failures;

    /**
     * Create the tables and record every failure reported.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createCallerTables();
        self::createMachineClientsTable();

        $failures = new \ArrayObject;

        Event::listen(AuthenticationFailed::class, static function (AuthenticationFailed $event) use ($failures): void {
            $failures->append($event);
        });

        $this->failures = $failures;
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropMachineClientsTable();
        $this->dropCallerTables();

        parent::tearDown();
    }

    /**
     * The bearer's caller is read once per request and admits another principal
     * of its identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBearersCallerIsReadOncePerRequest(): void
    {
        [$member, [$membership, $other]] = $this->seedMember('ada@example.test', 2);

        $session = $this->signedIn('ada@example.test', $membership);
        $request = $this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]);
        $callers = self::callers();
        $caller  = $callers->caller($request);

        self::assertNotNull($caller);
        self::assertSame(self::MEMBERS, $caller->guard);
        self::assertSame(CallerCredential::ACCESS, $caller->credential);
        self::assertSame($member->getKey(), $caller->identity->getAuthIdentifier());
        self::assertSame($membership->getKey(), $caller->principal?->getPrincipalIdentifier());
        self::assertNull($caller->tenant);
        self::assertSame($session->record->getKey(), $caller->session?->getSessionIdentifier());
        self::assertNull($caller->pending);
        self::assertNull($caller->scopes);
        self::assertTrue($caller->owns($other));

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertSame($caller, $callers->caller($request));
        self::assertSame(0, $queries);
    }

    /**
     * A guard made the default later in the request is read afresh, and the
     * first guard's caller is kept for it; a guest of a guard has no caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardChangedLaterInTheRequestIsReadAfresh(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $request = $this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]);
        $callers = self::callers();
        $caller  = $callers->caller($request);

        self::assertNotNull($caller);

        Auth::shouldUse(self::OTHERS);

        self::assertNull($callers->caller($request));

        Auth::shouldUse(self::MEMBERS);

        self::assertSame($caller, $callers->caller($request));
    }

    /**
     * A route that declares a credential of a named guard reads that guard,
     * whatever the default: its caller is the named guard's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeclaredGuardIsReadWhateverTheDefault(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test', guard: self::OTHERS);
        $request = $this->request('POST', body: ['refresh_token' => $session->tokens->refreshToken?->reveal()]);

        DeclaredCredential::refresh(self::OTHERS)->declareOn($request);

        $caller = self::callers()->caller($request);

        self::assertNotNull($caller);
        self::assertSame(self::OTHERS, $caller->guard);
        self::assertSame($session->record->getKey(), $caller->session?->getSessionIdentifier());
        self::assertCount(0, $this->failures);
    }

    /**
     * A bind or sign-out has the next ask read the guard as it is now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindOrSignOutForgetsTheCallerReadBefore(): void
    {
        [$ada, [$adas]] = $this->seedMember('ada@example.test');

        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);
        $request = $this->request('GET');
        $callers = self::callers();
        $guard   = Auth::manager()->guard(self::MEMBERS);

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertNull($callers->caller($request));

        $guard->login($ada, $adas);

        self::assertSame($ada, $callers->caller($request)?->identity);

        $guard->setUser($machine);

        self::assertSame($machine, $callers->caller($request)?->identity);

        $guard->logout();

        self::assertNull($callers->caller($request));
    }

    /**
     * Switching the principal or session has the next ask carry the new one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchingThePrincipalOrSessionForgetsTheCallerReadBefore(): void
    {
        [$ada, [$first, $second]] = $this->seedMember('ada@example.test', 2);

        $session = $this->signedIn('ada@example.test', $first);
        $request = $this->request('GET');
        $callers = self::callers();
        $guard   = Auth::manager()->guard(self::MEMBERS);

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->login($ada, $first);

        self::assertSame($first, $callers->caller($request)?->principal);

        $guard->setPrincipal($second);

        self::assertSame($second, $callers->caller($request)?->principal);

        $guard->setSession($session->record);

        self::assertSame($session->record, $callers->caller($request)?->session);
    }

    /**
     * What a `Login` listener read is not kept once the sign-in binds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALoginListenersReadIsNotKeptOnceTheSignInBinds(): void
    {
        [$ada, [$adas]] = $this->seedMember('ada@example.test');

        $request = $this->request('GET');
        $callers = self::callers();
        $guard   = Auth::manager()->guard(self::MEMBERS);

        /** @var \ArrayObject<int, ?\SineMacula\Laravel\Authentication\Callers\Caller> $read */
        $read = new \ArrayObject;

        self::assertInstanceOf(JwtGuard::class, $guard);

        Event::listen(Login::class, static function () use ($callers, $request, $read): void {
            $read->append($callers->caller($request));
        });

        $guard->login($ada, $adas);

        self::assertSame([null], $read->getArrayCopy());
        self::assertSame($ada, $callers->caller($request)?->identity);
    }

    /**
     * An access caller on any request is read again once its guard changes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccessCallerKeptOnAnyRequestIsReadAgainOnceTheGuardChanges(): void
    {
        [$ada, [$adas]] = $this->seedMember('ada@example.test');

        $this->request('GET');

        $callers = self::callers();
        $guard   = Auth::manager()->guard(self::MEMBERS);
        $other   = Request::create('/other');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->login($ada, $adas);

        self::assertSame($ada, $callers->caller($other)?->identity);

        $guard->logout();

        self::assertNull($callers->caller($other));

        $first = $this->request('GET');
        $guard = Auth::manager()->guard(self::MEMBERS);

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->login($ada, $adas);

        self::assertSame($ada, $callers->caller($first)?->identity);

        $guard->setRequest(Request::create('/next'));

        self::assertNull($callers->caller($first));
    }

    /**
     * A refresh caller is kept, not proven again, when its guard is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshCallerIsKeptWhenItsGuardIsBound(): void
    {
        [$ada, [$adas]] = $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test', $adas);
        $request = $this->request('POST', body: ['refresh_token' => $session->tokens->refreshToken?->reveal()]);
        $callers = self::callers();
        $guard   = Auth::manager()->guard(self::MEMBERS);

        self::assertInstanceOf(JwtGuard::class, $guard);

        DeclaredCredential::refresh(null)->declareOn($request);

        $caller = $callers->caller($request);

        self::assertNotNull($caller);

        $guard->login($ada, $adas);

        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertSame($caller, $callers->caller($request));
        self::assertSame(0, $queries);
        self::assertCount(0, $this->failures);
    }

    /**
     * The same machine bound again with other scopes is read afresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSameMachineBoundWithOtherScopesIsReadAfresh(): void
    {
        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);
        $request = $this->request('GET');
        $callers = self::callers();
        $guard   = Auth::manager()->guard('machine');

        self::assertInstanceOf(ApiKeyGuard::class, $guard);

        Auth::shouldUse('machine');

        $guard->authenticateAs($machine, $machine, scopes: ['read']);

        self::assertSame(['read'], $callers->caller($request)?->scopes);

        $guard->authenticateAs($machine, $machine, scopes: ['write']);

        self::assertSame(['write'], $callers->caller($request)?->scopes);
    }

    /**
     * Forgetting the request's callers has them read afresh, then kept again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgettingTheCallersHasThemReadAfresh(): void
    {
        $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test');
        $request = $this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]);
        $callers = self::callers();
        $caller  = $callers->caller($request);

        self::assertNotNull($caller);

        CallerCredentials::forget($request);

        $again = $callers->caller($request);

        self::assertNotSame($caller, $again);
        self::assertSame($caller->session?->getSessionIdentifier(), $again?->session?->getSessionIdentifier());
        self::assertSame($again, $callers->caller($request));
    }

    /**
     * The refresh credential's caller is the session it proves, its owner and
     * its principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRefreshCredentialsCallerIsTheSessionItProves(): void
    {
        [$member, [$membership, $other]] = $this->seedMember('ada@example.test', 2);

        $session = $this->signedIn('ada@example.test', $membership);
        $request = $this->request('POST', body: ['refresh_token' => $session->tokens->refreshToken?->reveal()]);

        DeclaredCredential::refresh(null)->declareOn($request);

        $caller = self::callers()->caller($request);

        self::assertNotNull($caller);
        self::assertSame(CallerCredential::REFRESH, $caller->credential);
        self::assertSame(self::MEMBERS, $caller->guard);
        self::assertSame($member->getKey(), $caller->identity->getAuthIdentifier());
        self::assertSame($membership->getKey(), $caller->principal?->getPrincipalIdentifier());
        self::assertSame($session->record->getKey(), $caller->session?->getSessionIdentifier());
        self::assertNull($caller->pending);
        self::assertNull($caller->scopes);
        self::assertTrue($caller->owns($other));
        self::assertCount(0, $this->failures);
    }

    /**
     * A refused refresh credential is reported once per request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedRefreshCredentialIsReportedOncePerRequest(): void
    {
        $callers = self::callers();
        $request = $this->request('POST', body: ['refresh_token' => 'not-a-refresh-token']);

        DeclaredCredential::refresh(null)->declareOn($request);

        self::assertNull($callers->caller($request));
        self::assertNull($callers->caller($request));
        self::assertCount(1, $this->failures);

        $failure = $this->failure(0);

        self::assertSame(AuthenticationFlow::REFRESH, $failure->flow);
        self::assertSame(FailureReason::TOKEN_INVALID, $failure->reason);
        self::assertSame(self::MEMBERS, $failure->context->guard);
        EventContextAssertions::assertIdentity(null, $failure->context);
        self::assertStringNotContainsString('not-a-refresh-token', serialize($failure));

        $again = $this->request('POST', body: ['refresh_token' => 'not-a-refresh-token']);

        DeclaredCredential::refresh(null)->declareOn($again);

        self::assertNull($callers->caller($again));
        self::assertCount(2, $this->failures);

        $none = $this->request('POST');

        DeclaredCredential::refresh(null)->declareOn($none);

        self::assertNull($callers->caller($none));
        self::assertCount(2, $this->failures);
    }

    /**
     * On a cookie application only a same-site request's refresh cookie is a
     * caller.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationsRefreshCallerIsOnlyASameSiteRequests(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $sameSite = ['REMOTE_ADDR' => '198.51.100.20', 'HTTP_ORIGIN' => 'http://localhost', 'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest'];
        $signIn   = Request::create('/auth/sign-in', 'POST', server: $sameSite);

        app()->instance('request', $signIn);

        Auth::forgetGuards();

        $input   = ['email' => 'ada@example.test', 'password' => self::MEMBER_PASSWORD];
        $session = Auth::sessions(self::BROWSER)->signIn('password', $input, SignInContext::fromRequest($signIn))->session;
        $cookie  = $session?->tokens->refreshCookie?->cookie();

        self::assertNotNull($session);
        self::assertNotNull($cookie);

        $this->cookieRequest([$cookie->getName() => (string) $cookie->getValue()], $sameSite);

        $caller = Auth::caller();

        self::assertNotNull($caller);
        self::assertSame([CallerCredential::REFRESH, self::BROWSER], [$caller->credential, $caller->guard]);
        self::assertSame($member->getKey(), $caller->identity->getAuthIdentifier());
        self::assertSame($membership->getKey(), $caller->principal?->getPrincipalIdentifier());
        self::assertSame($session->record->getKey(), $caller->session?->getSessionIdentifier());
        self::assertCount(0, $this->failures);

        $this->cookieRequest([$cookie->getName() => (string) $cookie->getValue()], ['REMOTE_ADDR' => '198.51.100.30', 'HTTP_USER_AGENT' => 'CrossSite/1.0']);

        self::assertNull(Auth::caller());
        self::assertNull(Auth::caller());
        self::assertCount(1, $this->failures);

        $failure = $this->failure(0);

        self::assertSame([AuthenticationFlow::REFRESH, FailureReason::CROSS_SITE_REQUEST, self::BROWSER], [$failure->flow, $failure->reason, $failure->context->guard]);
        self::assertSame(['198.51.100.30', 'CrossSite/1.0'], [$failure->context->client->ip, $failure->context->client->userAgent]);
        self::assertNull($failure->context->client->origin);
    }

    /**
     * A request that carries no refresh or pending credential reads no IP
     * address.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutACredentialReadsNoAddress(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_FORWARDED | Request::HEADER_X_FORWARDED_FOR);

        $conflicting = ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_FORWARDED' => 'for=198.51.100.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.2'];

        try {
            $refresh = $this->request('POST', $conflicting);

            DeclaredCredential::refresh(null)->declareOn($refresh);

            self::assertNull(self::callers()->caller($refresh));

            $pending = $this->request('POST', $conflicting);

            DeclaredCredential::pending(PendingAction::CHOOSE_PRINCIPAL->value, null)->declareOn($pending);

            self::assertNull(self::callers()->caller($pending));
            self::assertCount(0, $this->failures);

            $refused = $this->request('POST', ['REMOTE_ADDR' => '10.0.0.1', 'HTTP_X_FORWARDED_FOR' => '198.51.100.2'], ['refresh_token' => 'not-a-refresh-token']);

            DeclaredCredential::refresh(null)->declareOn($refused);

            self::assertNull(self::callers()->caller($refused));
            self::assertSame('198.51.100.2', $this->failure(0)->context->client->ip);
        } finally {
            Request::setTrustedProxies([], 0);
        }
    }

    /**
     * The pending credential's caller is the pending session it names.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePendingCredentialsCallerIsThePendingSessionItNames(): void
    {
        [$member] = $this->seedMember('ada@example.test', 2);

        $result = $this->memberSignIn('ada@example.test');

        self::assertNotNull($result->pending);

        foreach ([true, false] as $json) {

            $request = $this->request('POST', body: ['pending_credential' => $result->credential?->reveal()], json: $json);

            DeclaredCredential::pending(PendingAction::CHOOSE_PRINCIPAL->value, null)->declareOn($request);

            $caller = self::callers()->caller($request);

            self::assertNotNull($caller);
            self::assertSame(CallerCredential::PENDING, $caller->credential);
            self::assertSame($member->getKey(), $caller->identity->getAuthIdentifier());
            self::assertNull($caller->principal);
            self::assertNull($caller->scopes);
            self::assertSame($result->pending->session->getSessionIdentifier(), $caller->session?->getSessionIdentifier());
            self::assertNotNull($caller->pending);
            self::assertSame($result->pending->id, $caller->pending->id);
            self::assertCount(2, $caller->pending->principals);
        }

        self::assertCount(0, $this->failures);
    }

    /**
     * A pending credential is refused, or not read, as its session and
     * placement require.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingCredentialIsRefusedOrNotReadAsItShouldBe(): void
    {
        [$member] = $this->seedMember('ada@example.test', 2);

        $result = $this->memberSignIn('ada@example.test');

        self::assertNotNull($result->pending);

        $credential = (string) $result->credential?->reveal();

        self::assertNull($this->pendingCaller(PendingAction::VERIFY, ['pending_credential' => $credential]));
        self::assertCount(1, $this->failures);
        self::assertSame(FailureReason::PENDING_ACTION_NOT_ALLOWED, $this->failure(0)->reason);
        self::assertSame(AuthenticationFlow::SIGN_IN, $this->failure(0)->flow);
        self::assertSame(IdentifierCoercion::stringify($member->getKey()), $this->failure(0)->context->identityId);
        self::assertSame($result->pending->session->getSessionIdentifier(), $this->failure(0)->context->sessionId);
        self::assertSame('password', $this->failure(0)->context->method);

        foreach (['not-a-pending-credential', '', ['nested']] as $index => $refused) {
            self::assertNull($this->pendingCaller(PendingAction::CHOOSE_PRINCIPAL, ['pending_credential' => $refused]));
            self::assertSame(FailureReason::PENDING_INVALID, $this->failure($index + 1)->reason);
            self::assertSame(AuthenticationFlow::SIGN_IN, $this->failure($index + 1)->flow);
            EventContextAssertions::assertSession(null, $this->failure($index + 1)->context);
        }

        self::assertCount(4, $this->failures);

        $query = Request::create('/pending', 'GET', ['pending_credential' => $credential]);

        DeclaredCredential::pending(PendingAction::CHOOSE_PRINCIPAL->value, null)->declareOn($query);

        self::assertNull(self::callers()->caller($query));
        self::assertNull($this->pendingCaller(PendingAction::CHOOSE_PRINCIPAL, []));
        self::assertNull($this->pendingCaller(PendingAction::CHOOSE_PRINCIPAL, ['credential' => $credential]));
        self::assertCount(4, $this->failures);

        config()->set('authentication.session.pending_credential_field', 'credential');

        self::assertNotNull($this->pendingCaller(PendingAction::CHOOSE_PRINCIPAL, ['credential' => $credential]));
        self::assertNull($this->pendingCaller(PendingAction::CHOOSE_PRINCIPAL, ['pending_credential' => $credential]));
        self::assertCount(4, $this->failures);
    }

    /**
     * A pending credential field that PHP would file under another key is a
     * misconfiguration, refused when the caller is read.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMalformedPendingCredentialFieldFailsClosed(): void
    {
        config()->set('authentication.session.pending_credential_field', 'pending.credential');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.session.pending_credential_field must be a field name without `.`, spaces or brackets.');

        $this->pendingCaller(PendingAction::CHOOSE_PRINCIPAL, ['pending' => ['credential' => 'value']]);
    }

    /**
     * A guard that is not one of the package's has no caller to read: a
     * misconfiguration.
     *
     * @return void
     */
    public function testAGuardThatIsNotThePackagesIsRefused(): void
    {
        config()->set('auth.guards.web', ['driver' => 'session', 'provider' => 'caller_members']);

        Auth::shouldUse('web');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The caller of a request is read from a package guard; [web] is not one.');

        self::callers()->caller($this->request('GET'));
    }

    /**
     * An API key's caller is its machine, with no session, and admits no other
     * principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApiKeysCallerIsItsMachineAndAdmitsNoOtherPrincipal(): void
    {
        [, [$membership]] = $this->seedMember('ada@example.test');

        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);

        $this->request('GET');

        $key     = Auth::apiKeys('machine')->issue($machine, $machine)->key()->reveal();
        $request = $this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $key]);

        Auth::shouldUse('machine');

        $caller = self::callers()->caller($request);

        self::assertNotNull($caller);
        self::assertSame('machine', $caller->guard);
        self::assertSame(CallerCredential::ACCESS, $caller->credential);
        self::assertSame($machine->getKey(), $caller->identity->getAuthIdentifier());
        self::assertSame($machine->getKey(), $caller->principal?->getPrincipalIdentifier());
        self::assertNull($caller->session);
        self::assertSame([], $caller->scopes);
        self::assertTrue($caller->owns($machine));
        self::assertFalse($caller->owns($membership));
    }

    /**
     * An API key's caller carries the scopes the key was granted, in order, and
     * `[]` for a key granted none, which is not `null`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApiKeysCallerCarriesTheScopesItWasGranted(): void
    {
        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);

        $this->request('GET');

        $scoped = Auth::apiKeys('machine')->issue($machine, $machine, ['read', 'write'])->key()->reveal();
        $bare   = Auth::apiKeys('machine')->issue($machine, $machine)->key()->reveal();

        Auth::shouldUse('machine');

        self::assertSame(['read', 'write'], self::callers()->caller($this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $scoped]))?->scopes);
        self::assertSame([], self::callers()->caller($this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $bare]))?->scopes);
    }

    /**
     * A client-credentials access token's caller carries the scopes the token
     * was validated to grant, which may be fewer than its key holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAClientCredentialsTokensCallerCarriesTheScopesItGrants(): void
    {
        $machine = MachineClient::query()->create(['email' => 'robot@example.test']);

        $this->request('GET');

        $issued = Auth::apiKeys('m2m')->issue($machine, $machine, ['read', 'write']);
        $secret = substr($issued->key()->reveal(), 20);

        foreach ([['write', ['write']], [null, ['read', 'write']]] as [$asked, $granted]) {

            $result = Auth::clientCredentials('m2m')->exchange(self::basicClient($issued->summary->publicId, $secret, $asked), self::requestClient());

            self::assertNotNull($result->accessToken);

            Auth::shouldUse('m2m');

            $caller = self::callers()->caller($this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $result->accessToken->reveal()]));

            self::assertNotNull($caller);
            self::assertSame(CallerCredential::ACCESS, $caller->credential);
            self::assertNull($caller->session);
            self::assertSame($granted, $caller->scopes);
        }
    }

    /**
     * A human's access token, with or without a session, has no scope ceiling:
     * its caller's scopes are `null`, not `[]`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHumansAccessTokenHasNoScopeCeiling(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $tokens = Auth::jwt(self::MEMBERS);

        self::assertNotNull($tokens);

        $accessOnly = $tokens->issueAccessToken($member, $membership, null, null)->reveal();

        $caller = self::callers()->caller($this->request('GET', ['HTTP_AUTHORIZATION' => 'Bearer ' . $accessOnly]));

        self::assertNotNull($caller);
        self::assertNull($caller->session);
        self::assertNull($caller->scopes);
    }

    /**
     * Register the members' guards, a cookie application over the same members,
     * and the machines' API key guard.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureCallerGuards($config);

        $config->set('auth.providers.machines', ['driver' => 'model', 'model' => MachineClient::class]);
        $config->set('auth.guards.m2m', ['driver' => 'jwt', 'provider' => 'machines', 'application' => ['methods' => ['client_credentials']]]);
        $config->set('auth.guards.machine', ['driver' => 'api_key', 'provider' => 'machines', 'application' => ['methods' => ['api_key']]]);
        $config->set('auth.guards.' . self::BROWSER, [
            'driver'        => 'jwt',
            'provider'      => 'caller_members',
            'application'   => ['methods' => ['password']],
            'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/auth']],
        ]);
    }

    /**
     * The caller credentials, over the package's auth manager, the
     * configuration and the dispatcher.
     *
     * @return \SineMacula\Laravel\Authentication\Callers\CallerCredentials
     */
    private static function callers(): CallerCredentials
    {
        $auth = app('auth');

        self::assertInstanceOf(AuthManager::class, $auth);

        return new CallerCredentials($auth, app(ConfigRepository::class), app(Dispatcher::class));
    }

    /**
     * Bind a request with the server variables and body, JSON or form, as the
     * request being served, on guards resolved afresh.
     *
     * @param  string  $method
     * @param  array<string, string>  $server
     * @param  array<string, mixed>  $body
     * @param  bool  $json
     * @return \Illuminate\Http\Request
     */
    private function request(string $method, array $server = [], #[\SensitiveParameter] array $body = [], bool $json = true): Request
    {
        $request = $json
            ? Request::create('/bound', $method, server: [...$server, 'CONTENT_TYPE' => 'application/json'], content: (string) json_encode($body))
            : Request::create('/bound', $method, $body, server: $server);

        app()->instance('request', $request);

        Auth::forgetGuards();

        return $request;
    }

    /**
     * Bind a cookie application request whose route declares the refresh
     * credential.
     *
     * @param  array<string, string>  $cookies
     * @param  array<string, string>  $server
     * @return void
     */
    private function cookieRequest(#[\SensitiveParameter] array $cookies, array $server): void
    {
        $request = Request::create('/auth/refresh', 'POST', [], $cookies, [], $server);

        DeclaredCredential::refresh(self::BROWSER)->declareOn($request);

        app()->instance('request', $request);

        Auth::forgetGuards();
    }

    /**
     * The caller of a JSON request whose route declares the pending credential
     * for the action, with the body.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @param  array<string, mixed>  $body
     * @return ?\SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \Throwable
     */
    private function pendingCaller(PendingAction $action, #[\SensitiveParameter] array $body): ?Caller
    {
        $request = $this->request('POST', body: $body);

        DeclaredCredential::pending($action->value, null)->declareOn($request);

        return self::callers()->caller($request);
    }

    /**
     * The failure reported at the index, in order.
     *
     * @param  int  $index
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    private function failure(int $index): AuthenticationFailed
    {
        $failure = $this->failures[$index] ?? null;

        self::assertInstanceOf(AuthenticationFailed::class, $failure);

        return $failure;
    }
}
