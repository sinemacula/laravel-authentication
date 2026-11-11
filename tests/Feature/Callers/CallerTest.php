<?php

declare(strict_types = 1);

namespace Tests\Feature\Callers;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithCallers;
use Tests\Integration\Fixtures\CallerMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\EncryptedDescriptionSession;
use Tests\Integration\Fixtures\PlainTeam;
use Tests\Integration\Fixtures\RelationSessionsIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubBareSession;

/**
 * Feature tests of whether a session, identity or principal model is the
 * caller's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Caller::class)]
final class CallerTest extends TestCase
{
    use InteractsWithCallers;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createCallerTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropCallerTables();

        parent::tearDown();
    }

    /**
     * With the access credential, every session of the guard and member is the
     * caller's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithTheAccessCredentialEverySessionOfTheGuardAndMemberIsTheCallers(): void
    {
        $this->seedMember('ada@example.test');
        $this->seedMember('grace@example.test');

        $current = $this->signedIn('ada@example.test');
        $another = $this->signedIn('ada@example.test');
        $others  = $this->signedIn('ada@example.test', guard: self::OTHERS);
        $graces  = $this->signedIn('grace@example.test');
        $caller  = $this->bearerCaller($current);

        self::assertTrue($caller->owns(self::stored($current)));
        self::assertTrue($caller->owns(self::stored($another)));
        self::assertFalse($caller->owns(self::stored($others)));
        self::assertFalse($caller->owns(self::stored($graces)));
        self::assertFalse($caller->owns(new StubBareSession));
    }

    /**
     * With a refresh credential, only the session it proves is the caller's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithARefreshCredentialOnlyTheSessionItProvesIsTheCallers(): void
    {
        $this->seedMember('ada@example.test');

        $proven  = $this->signedIn('ada@example.test');
        $another = $this->signedIn('ada@example.test');
        $request = $this->request(['refresh_token' => $proven->tokens->refreshToken?->reveal()]);

        DeclaredCredential::refresh(null)->declareOn($request);

        $caller = Auth::caller();

        self::assertNotNull($caller);
        self::assertSame(CallerCredential::REFRESH, $caller->credential);
        self::assertTrue($caller->owns(self::stored($proven)));
        self::assertFalse($caller->owns(self::stored($another)));
        self::assertFalse($caller->owns(EncryptedDescriptionSession::query()->whereKey($proven->record->getKey())->firstOrFail()));
    }

    /**
     * With a pending credential, the pending session and the memberships it
     * offers are the caller's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPendingCredentialOwnsItsSessionAndOfferedMemberships(): void
    {
        [$member, [$first, $second]] = $this->seedMember('ada@example.test', 2);
        [, [$graces]]                = $this->seedMember('grace@example.test');

        $active = $this->signedIn('ada@example.test', $first);
        $result = $this->memberSignIn('ada@example.test');

        self::assertNotNull($result->pending);

        $request = $this->request(['pending_credential' => $result->credential?->reveal()]);

        DeclaredCredential::pending(PendingAction::CHOOSE_PRINCIPAL->value, null)->declareOn($request);

        $caller = Auth::caller();

        self::assertNotNull($caller);
        self::assertNull($caller->principal);
        self::assertTrue($caller->owns(Session::query()->whereKey($result->pending->session->getSessionIdentifier())->firstOrFail()));
        self::assertFalse($caller->owns(self::stored($active)));
        self::assertTrue($caller->owns($member));
        self::assertTrue($caller->owns($first));
        self::assertTrue($caller->owns($second));
        self::assertFalse($caller->owns($graces));
    }

    /**
     * The caller's identity is judged by class and key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersIdentityIsJudgedByClassAndKey(): void
    {
        [$member] = $this->seedMember('ada@example.test');
        [$grace]  = $this->seedMember('grace@example.test');

        $caller = $this->bearerCaller($this->signedIn('ada@example.test'));

        self::assertTrue($caller->owns(CallerMember::query()->whereKey($member->getKey())->firstOrFail()));
        self::assertFalse($caller->owns($grace));
        self::assertFalse($caller->owns((new RelationSessionsIdentity)->forceFill(['id' => $member->getKey()])));
    }

    /**
     * A principal is the caller's when it acts as it or its identity may use
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalIsTheCallersWhenItActsAsItOrItsIdentityMayUseIt(): void
    {
        [, [$first, $second, $deleted]] = $this->seedMember('ada@example.test', 3);
        [, [$graces]]                   = $this->seedMember('grace@example.test');

        $caller = $this->bearerCaller($this->signedIn('ada@example.test', $first));

        $deleted->delete();

        self::assertTrue($caller->owns($first));
        self::assertTrue($caller->owns($second));
        self::assertFalse($caller->owns($graces));
        self::assertFalse($caller->owns($deleted));
        self::assertFalse($caller->owns((new ChoosingMembership)->forceFill(['id' => $second->getKey()])));
    }

    /**
     * Whether the caller's own session, identity and current principal are its
     * own is answered from the credential, without a query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallersOwnInstancesAreJudgedWithoutAQuery(): void
    {
        [$member, [$membership]] = $this->seedMember('ada@example.test');

        $session = $this->signedIn('ada@example.test', $membership);
        $caller  = $this->bearerCaller($session);
        $stored  = self::stored($session);
        $queries = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertTrue($caller->owns($stored));
        self::assertTrue($caller->owns($member));
        self::assertTrue($caller->owns($membership));
        self::assertSame(0, $queries);
    }

    /**
     * A principal is admitted by its id only through the guard's session
     * service.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalIsAdmittedOnlyThroughTheGuardsSessionService(): void
    {
        [$member, [$first, $second]] = $this->seedMember('ada@example.test', 2);

        $session = $this->signedIn('ada@example.test', $first);

        $sessionless = new Caller(self::MEMBERS, CallerCredential::ACCESS, $member, $first, null, null, sessions: Auth::sessions(self::MEMBERS));
        $serviceless = new Caller(self::MEMBERS, CallerCredential::ACCESS, $member, $first, null, $session->record);
        $unproven    = new Caller(self::MEMBERS, CallerCredential::REFRESH, $member, $first, null, null);

        self::assertTrue($sessionless->owns($second));
        self::assertFalse($serviceless->owns($second));
        self::assertTrue($serviceless->owns($first));
        self::assertFalse($unproven->owns(self::stored($session)));
    }

    /**
     * A model that is not a session, an identity or a principal is never the
     * caller's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnyOtherModelIsNotTheCallers(): void
    {
        $this->seedMember('ada@example.test');

        self::assertFalse($this->bearerCaller($this->signedIn('ada@example.test'))->owns(new PlainTeam));
    }

    /**
     * Register the members' guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureCallerGuards($app->make(ConfigRepository::class));
    }

    /**
     * The caller of a request that carries the session's access token.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \Throwable
     */
    private function bearerCaller(SignedInSession $session): Caller
    {
        $this->request([], ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]);

        $caller = Auth::caller();

        self::assertNotNull($caller);
        self::assertSame(CallerCredential::ACCESS, $caller->credential);

        return $caller;
    }

    /**
     * Bind a JSON request with the body and server variables as the request
     * being served, on guards resolved afresh.
     *
     * @param  array<string, mixed>  $body
     * @param  array<string, string>  $server
     * @return \Illuminate\Http\Request
     */
    private function request(#[\SensitiveParameter] array $body, array $server = []): Request
    {
        $request = Request::create('/caller', 'POST', server: [...$server, 'CONTENT_TYPE' => 'application/json'], content: (string) json_encode($body));

        app()->instance('request', $request);

        Auth::forgetGuards();

        return $request;
    }

    /**
     * The session's row, read afresh as the shipped session model.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private static function stored(SignedInSession $session): Session
    {
        return Session::query()->whereKey($session->record->getKey())->firstOrFail();
    }
}
