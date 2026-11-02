<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\RefreshCredential;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of reading who the request's refresh credential would sign in
 * again, without rotating it or binding anything: the owner, principal, tenant
 * and session a refresh would admit, with where the credential was read from;
 * the reason the transport, the session or the admission refuses it, returned
 * for the caller to report; and nothing for a request that carries none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshCredential::class)]
#[CoversClass(SessionRefresh::class)]
#[CoversClass(SessionService::class)]
#[CoversTrait(RefreshesSessions::class)]
final class RefreshCredentialTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> Every event a refresh or a sign-out could dispatch. */
    private const array EVENTS = [Attempting::class, Failed::class, AuthenticationFailed::class, SessionRevoked::class, Logout::class];

    /** @var string A rotation id the tests store the digest of, so they can issue tokens that carry it. */
    private const string KNOWN_ROTATION = 'known-rotation-id';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A refresh token in the body is the credential of its session's owner,
     * acting as the principal the session records, in no tenant: the session
     * keeps its rotation, the guard stays a guest, and nothing is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenIsTheCredentialOfWhoARefreshWouldSignInAgain(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $before   = (array) DB::table('authentication_sessions')->sole();

        $this->recordEvents(self::EVENTS);

        $credential = $this->serving(body: ['refresh_token' => self::refreshOf($session)])->refreshCredentialFromRequest();

        self::assertInstanceOf(RefreshCredential::class, $credential);
        self::assertTrue($identity->is($credential->identity));
        self::assertSame($identity->getPrincipalIdentifier(), $credential->principal->getPrincipalIdentifier());
        self::assertNull($credential->tenant);
        self::assertSame($session->record->getKey(), $credential->session->getKey());
        self::assertSame(RefreshTokenSource::BODY, $credential->source);
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());
        self::assertTrue(Auth::guard('api')->guest());
    }

    /**
     * A member's refresh token in the header is the credential of the
     * membership the session acts as, in the tenant it is active in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMembersCredentialCarriesItsActiveTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session    = $this->signedIn('members', 'member@example.test');
        $credential = $this->serving(['HTTP_X_REFRESH_TOKEN' => self::refreshOf($session)], guard: 'members')->refreshCredentialFromRequest();

        self::assertInstanceOf(RefreshCredential::class, $credential);
        self::assertTrue($member->is($credential->identity));
        self::assertSame($membership->getPrincipalIdentifier(), $credential->principal->getPrincipalIdentifier());
        self::assertSame($tenant->getTenantIdentifier(), $credential->tenant?->getTenantIdentifier());
        self::assertSame(RefreshTokenSource::HEADER, $credential->source);
    }

    /**
     * A request that carries no refresh token has no credential.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutATokenHasNoCredential(): void
    {
        $this->recordEvents(self::EVENTS);

        self::assertNull($this->serving()->refreshCredentialFromRequest());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Each refusal is returned as its reason and reported by nothing, for the
     * caller to report: the transport's, the session's, and the admission's, an
     * owner deactivated since the sign-in and a principal the session no longer
     * records among them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryRefusalIsReturnedForTheCallerToReport(): void
    {
        $identity   = $this->seedIdentity();
        $other      = $this->seedIdentity('grace@example.test');
        $session    = $this->signedIn();
        $inactive   = $this->signedIn('api', 'grace@example.test');
        $unrecorded = $this->signedIn();

        DB::table('integration_identities')->where('id', $other->getKey())->update(['is_active' => false]);

        Session::query()->whereKey($unrecorded->record->getKey())->update([
            'principal_id' => IdentifierCoercion::stringify($other->getKey()),
            'refresh_key'  => RefreshTokenHasher::hash(self::KNOWN_ROTATION),
        ]);

        $unnamed = Auth::jwt('api')->issueRefreshToken($unrecorded->record, self::KNOWN_ROTATION)->reveal();
        $cases   = [
            'conflicting carriers' => [['HTTP_X_REFRESH_TOKEN' => 'one-token'], ['refresh_token' => 'another-token'], FailureReason::REFRESH_TOKEN_CONFLICT],
            'not a token'          => [[], ['refresh_token' => 'not-a-token'], FailureReason::TOKEN_INVALID],
            'an inactive owner'    => [[], ['refresh_token' => self::refreshOf($inactive)], FailureReason::IDENTITY_INACTIVE],
            'an unrecorded actor'  => [[], ['refresh_token' => $unnamed], FailureReason::SESSION_PRINCIPAL_MISMATCH],
        ];

        $this->recordEvents(self::EVENTS);

        foreach ($cases as $case => [$server, $body, $reason]) {
            self::assertSame($reason, $this->serving($server, $body)->refreshCredentialFromRequest(), $case);
        }

        self::assertSame([], $this->recordedClasses());
        self::assertSame(0, Session::query()->whereNotNull('revoked_at')->count());

        $credential = $this->serving(body: ['refresh_token' => self::refreshOf($session)])->refreshCredentialFromRequest();

        self::assertInstanceOf(RefreshCredential::class, $credential);
        self::assertTrue($identity->is($credential->identity));
    }

    /**
     * A replayed token is refused as `rotation_reuse` and revokes its session,
     * as a refresh does: the revocation's `SessionRevoked` is the one event
     * dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplayRevokesItsSessionAndIsReportedOnlyByTheRevocation(): void
    {
        $this->seedIdentity();

        $session  = $this->signedIn();
        $replaced = self::refreshOf($session);

        self::assertTrue($this->sessions()->refresh($replaced)->isRefreshed());

        $this->moveTo(CarbonImmutable::now()->addMinutes(2));
        $this->recordEvents(self::EVENTS);

        self::assertSame(FailureReason::ROTATION_REUSE, $this->serving(body: ['refresh_token' => $replaced])->refreshCredentialFromRequest());
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::ROTATION_REUSE, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame('rotation_reuse', Session::query()->whereKey($session->record->getKey())->value('revoked_reason'));
    }

    /**
     * Configure the session guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The refresh token a body application's session carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function refreshOf(SignedInSession $session): string
    {
        $token = $session->tokens->refreshToken?->reveal();

        self::assertIsString($token);

        return $token;
    }

    /**
     * Sign the identity with the email in on the guard.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The session service of the guard, on a guard resolved afresh for a
     * request from the test client with the server values and body.
     *
     * @param  array<string, string>  $server
     * @param  array<string, string>  $body
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function serving(array $server = [], array $body = [], string $guard = 'api'): SessionService
    {
        app()->instance('request', Request::create('/sessions/me', 'POST', $body, server: [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
            ...$server,
        ]));

        Auth::forgetGuards();

        return Auth::sessions($guard);
    }

    /**
     * Move the clock, and the token library's, to the moment.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private function moveTo(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();
    }
}
