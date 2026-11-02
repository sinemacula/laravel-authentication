<?php

declare(strict_types = 1);

namespace Tests\Feature\Callers;

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
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use Tests\Concerns\InteractsWithCallers;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of how a request's caller is read from the credential its route
 * declares: the guard's own bearer or API key, the refresh credential or the
 * pending credential, each with what the caller needs to admit a principal by
 * its id; at most once per request for a guard and a credential, afresh for a
 * guard changed later; a refused credential reported once; and a guard that is
 * not the package's refused.
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
     * The bearer's caller is the guard's identity, principal, tenant and
     * session, read once for the request: asked again, it is the same caller,
     * read without a query. It admits another principal of its identity by its
     * id, as the guard's session service does.
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
     * The refresh credential's caller is who the refresh would sign in again:
     * the session it proves, its owner and the principal it records; it admits
     * another principal of its owner by its id.
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
        self::assertTrue($caller->owns($other));
        self::assertCount(0, $this->failures);
    }

    /**
     * A refused refresh credential is reported once for the request, however
     * often the caller is asked, with the guard and the client but not the
     * token, and again for another request; one the request does not carry is
     * not reported.
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
        self::assertNull($failure->context->identity);
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
     * The pending credential's caller is the pending session it names, read
     * from the JSON body or the form body, while the session allows the action:
     * its member, no principal while the choice is outstanding, and the pending
     * session itself.
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
            self::assertSame($result->pending->session->getSessionIdentifier(), $caller->session?->getSessionIdentifier());
            self::assertNotNull($caller->pending);
            self::assertSame($result->pending->id, $caller->pending->id);
            self::assertCount(2, $caller->pending->principals);
        }

        self::assertCount(0, $this->failures);
    }

    /**
     * The pending credential is refused for an action its session does not
     * allow now, reported with the session's member and session; an unknown or
     * empty one, or one that is not a string, as `pending_invalid`; one that is
     * only in the query string, or absent, is not read and not reported; and
     * the field read is the configured one.
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
        self::assertSame($member->getKey(), $this->failure(0)->context->identity?->getAuthIdentifier());
        self::assertSame($result->pending->session->getSessionIdentifier(), $this->failure(0)->context->session?->getSessionIdentifier());
        self::assertSame('password', $this->failure(0)->context->method);

        foreach (['not-a-pending-credential', '', ['nested']] as $index => $refused) {
            self::assertNull($this->pendingCaller(PendingAction::CHOOSE_PRINCIPAL, ['pending_credential' => $refused]));
            self::assertSame(FailureReason::PENDING_INVALID, $this->failure($index + 1)->reason);
            self::assertSame(AuthenticationFlow::SIGN_IN, $this->failure($index + 1)->flow);
            self::assertNull($this->failure($index + 1)->context->session);
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
     * An API key's caller is the machine the key authenticates, its own
     * principal, with no session; its guard keeps no sessions, so it admits no
     * other principal by its id.
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
        self::assertTrue($caller->owns($machine));
        self::assertFalse($caller->owns($membership));
    }

    /**
     * Register the members' guards and the machines' API key guard.
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
        $config->set('auth.guards.machine', ['driver' => 'api_key', 'provider' => 'machines', 'application' => ['methods' => ['api_key']]]);
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
