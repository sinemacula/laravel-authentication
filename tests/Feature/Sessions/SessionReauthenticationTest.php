<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ProvesSessions;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Passwords\RecordingTimebox;
use Tests\Fixtures\Sessions\RefusalIgnoringSignIn;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of reauthenticating a session with its identity's first factor:
 * a new access token whose authentication time is renewed and nothing else, the
 * proof recorded and reported once committed, the attempt counted as a
 * sign-in's and given back on success, and every refusal answered and reported,
 * never thrown, never saying whose a credential was.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionReauthentication::class)]
#[CoversClass(ProofIssuance::class)]
#[CoversClass(AccessTokenResult::class)]
#[CoversClass(Reauthenticated::class)]
#[CoversTrait(ProvesSessions::class)]
final class SessionReauthenticationTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions;

    /** @var int A credential timebox budget that leaves a wait after each check, in microseconds. */
    private const int BUDGET = 400000;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and register the route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->clockAt($this->now);
        $this->createSessionTables();

        Route::middleware('auth:api')->post('/reauthenticate', static function (Request $request): array {

            $session = Auth::session();

            assert($session !== null);

            $result = Auth::sessions('api')->reauthenticate(
                $session,
                'password',
                ['email' => $request->string('email')->toString(), 'password' => $request->string('password')->toString()],
            );

            return ['access_token' => $result->accessToken, 'reason' => $result->reason?->value];
        });
    }

    /**
     * Release the clocks and drop the tables.
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
     * Reauthenticating with the password through a route behind `auth:api`
     * answers a new access token for the session; the session keeps its refresh
     * token and deadlines.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationOverHttpIssuesANewAccessTokenOnly(): void
    {
        $signedIn = $this->signedIn();
        $before   = self::refreshState();

        $this->clockAt($this->now->addHour());

        $answer = $this->withToken($signedIn->tokens->accessToken)->postJson('/reauthenticate', self::credentials())->assertOk()->json();

        self::assertIsArray($answer);
        self::assertNull($answer['reason']);
        self::assertIsString($answer['access_token']);
        self::assertSame($before, self::refreshState());
        self::assertTrue($this->sessions()->refresh($signedIn->tokens->refreshToken)->isRefreshed());
    }

    /**
     * A reauthentication records a first-factor reauthentication proof for
     * `reauthenticate`, through the method, with the method's channel, values
     * and no evaluation, reports it with `Reauthenticated` once committed, and
     * gives back every attempt slot it took.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationRecordsTheProofAndGivesTheSlotsBack(): void
    {
        $signedIn = $this->signedIn();

        $this->clockAt($this->now->addHour());
        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class]);

        $result = $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials());

        self::assertTrue($result->isIssued());
        self::assertSame($signedIn->record->getKey(), $result->session?->getKey());
        self::assertNotNull($result->expiresAt);

        $proof = SessionProof::query()->where('kind', 'first_factor_reauthentication')->sole();

        self::assertSame(
            ['reauthenticate', 'password', 'password', ['pwd'], null, null],
            [$proof->purpose, $proof->method, $proof->channel_kind, $proof->methods, $proof->accepted, $proof->multifactor],
        );
        self::assertSame($this->now->addHour()->getTimestamp(), $proof->authenticated_at->getTimestamp());
        self::assertSame([Reauthenticated::class], $this->recordedClasses());
        self::assertSame(['api', 'password'], [$this->recordedEvent(Reauthenticated::class)->context->guard, $this->recordedEvent(Reauthenticated::class)->context->method]);

        $account = AccountAttempts::account($signedIn->identity);

        self::assertSame([0, 0], [self::counterHits('sign_in', 'per_account', $account), self::counterHits('api', 'sign_in', 'per_ip', self::CLIENT_IP)]);
    }

    /**
     * The new token's `auth_time` is the reauthentication's, and its `amr` is
     * the session's as it was: a reauthentication adds no value and no `mfa`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationRenewsTheAuthenticationTimeOnly(): void
    {
        $signedIn = $this->signedIn();

        $this->clockAt($this->now->addHour());

        $result = $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials());
        $claims = Auth::manager()->jwt('api')->parse((string) $result->accessToken, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame([$this->now->addHour()->getTimestamp(), ['pwd']], [$claims['auth_time'] ?? null, $claims['amr'] ?? null]);
    }

    /**
     * A wrong password, and another identity's right one, are both refused as
     * invalid credentials, the same way, and recorded nowhere; the attempt
     * stays counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongOrForeignCredentialIsInvalid(): void
    {
        $signedIn = $this->signedIn();

        $this->seedIdentity('grace@example.test');
        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class]);

        $wrong   = $this->sessions()->reauthenticate($signedIn->record, 'password', ['email' => 'ada@example.test', 'password' => 'wrong']);
        $foreign = $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials('grace@example.test'));

        self::assertSame([FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS], [$wrong->reason, $foreign->reason]);
        self::assertSame([AuthenticationFailed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::REAUTHENTICATION, $this->recordedEvent(AuthenticationFailed::class)->flow);
        self::assertSame(0, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
        self::assertSame(1, self::counterHits('sign_in', 'per_account', AccountAttempts::account($signedIn->identity)));
    }

    /**
     * A method the application does not allow is refused before anything is
     * counted, and a machine credential kind is no method at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodTheApplicationDoesNotAllowIsRefused(): void
    {
        $signedIn = $this->signedIn();

        DB::table('rate_limits')->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->reauthenticate($signedIn->record, 'passkey', [])->reason);
        self::assertSame(
            [AuthenticationFlow::REAUTHENTICATION, FailureReason::METHOD_NOT_ALLOWED],
            [$this->recordedEvent(AuthenticationFailed::class)->flow, $this->recordedEvent(AuthenticationFailed::class)->reason],
        );
        self::assertSame(0, DB::table('rate_limits')->count());

        $this->expectException(\InvalidArgumentException::class);

        $this->sessions()->reauthenticate($signedIn->record, 'api_key', []);
    }

    /**
     * Once the identifier has used up its sign-in attempts, a reauthentication
     * is rate limited, with the wait, before the password is checked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationIsRateLimitedAsASignIn(): void
    {
        $signedIn = $this->signedIn();

        foreach (range(1, 5) as $attempt) {
            $this->sessions()->reauthenticate($signedIn->record, 'password', ['email' => 'ada@example.test', 'password' => "wrong {$attempt}"]);
        }

        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials());

        self::assertSame(FailureReason::RATE_LIMITED, $result->reason);
        self::assertIsInt($result->retryAfter);
        self::assertSame($result->retryAfter, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
    }

    /**
     * A session that is revoked, ended, another guard's or gone takes no
     * reauthentication, and nothing is counted for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotLiveTakesNoReauthentication(): void
    {
        $signedIn = $this->signedIn();
        $admin    = $this->sessions('admin')->signIn('password', self::credentials())->session;

        self::assertNotNull($admin);

        DB::table('rate_limits')->delete();

        self::assertSame(FailureReason::SESSION_GUARD_MISMATCH, $this->sessions()->reauthenticate($admin->record, 'password', self::credentials())->reason);

        DB::table('authentication_sessions')->where('id', $signedIn->record->getKey())->update(['revoked_at' => $this->now]);

        self::assertSame(FailureReason::SESSION_REVOKED, $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials())->reason);

        DB::table('authentication_sessions')->where('id', $signedIn->record->getKey())->update(['revoked_at' => null, 'idle_expires_at' => $this->now]);

        self::assertSame(FailureReason::SESSION_EXPIRED, $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials())->reason);
        self::assertSame(FailureReason::SESSION_UNKNOWN, $this->sessions()->reauthenticate(new Session, 'password', self::credentials())->reason);
        self::assertSame(0, DB::table('rate_limits')->count());
        self::assertSame(0, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
    }

    /**
     * A session owned by a machine takes no reauthentication, before anything
     * is counted; one whose recorded principal no longer resolves as that very
     * principal is refused once admitted again, under the lock. Neither records
     * a proof, and each is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMachinesOrAnotherPrincipalsSessionTakesNoReauthentication(): void
    {
        $signedIn = $this->signedIn();

        DB::table('rate_limits')->delete();
        DB::table('authentication_sessions')->update(['authenticatable_type' => MachineClient::class]);

        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class]);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials())->reason);
        self::assertSame(0, DB::table('rate_limits')->count());

        DB::table('authentication_sessions')->update(['authenticatable_type' => IntegrationIdentity::class, 'principal_type' => 'another-model']);

        self::assertSame(FailureReason::SESSION_PRINCIPAL_MISMATCH, $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials())->reason);
        self::assertSame([AuthenticationFailed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(
            [[AuthenticationFlow::REAUTHENTICATION, FailureReason::MACHINE_IDENTITY], [AuthenticationFlow::REAUTHENTICATION, FailureReason::SESSION_PRINCIPAL_MISMATCH]],
            array_map(static fn (object $event): array => $event instanceof AuthenticationFailed ? [$event->flow, $event->reason] : [], $this->recorded),
        );
        self::assertSame(0, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
    }

    /**
     * An account with no attempts left is not reauthenticated, whether the
     * method honours the account's refusal or checks the secret anyway: the
     * result answers `invalid_credentials` with no wait, so it never says the
     * account exists, while `AuthenticationFailed` carries the account's limit
     * and wait; nothing is recorded or given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccountOutOfAttemptsIsNotReauthenticated(): void
    {
        $box      = $this->recordingTimebox();
        $signedIn = $this->signedIn();

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->andReturnUsing(
            static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, $subject->account === null ? null : 90),
        );
        $limiter->shouldReceive('release')->never();

        app()->instance(AttemptLimiter::class, $limiter);

        $manager = app(SignInMethodManager::class);

        $manager->forgetDrivers();
        $manager->extend('trusted', fn (): SignInMethod => new RefusalIgnoringSignIn);

        foreach (['password', 'trusted'] as $method) {

            $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class]);

            $result = $this->sessions()->reauthenticate($signedIn->record, $method, self::credentials());

            self::assertSame([FailureReason::INVALID_CREDENTIALS, null], [$result->reason, $result->retryAfter], $method);

            $failure = $this->recordedEvent(AuthenticationFailed::class);

            self::assertSame([FailureReason::ACCOUNT_RATE_LIMITED, 90], [$failure->reason, $failure->retryAfter], $method);
        }

        self::assertSame(0, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
        self::assertSame([true, false, false], $box->endedEarly);
        self::assertCount(2, $box->waits);
    }

    /**
     * A reauthentication runs in the guard's credential timebox and cuts it
     * short only once the session's own owner's credential has verified: a
     * wrong password and another identity's right one each wait the box out,
     * after a sign-in on the same guard cut its own short, so a valid password
     * for some other account takes as long as a wrong one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheOwnersVerifiedCredentialCutsTheTimeboxShort(): void
    {
        $box = $this->recordingTimebox();

        $this->seedIdentity();
        $this->seedIdentity('grace@example.test');

        $sessions = $this->sessions();
        $signedIn = $sessions->signIn('password', self::credentials())->session;

        self::assertNotNull($signedIn);

        $wrong   = $sessions->reauthenticate($signedIn->record, 'password', ['email' => 'ada@example.test', 'password' => 'wrong']);
        $foreign = $sessions->reauthenticate($signedIn->record, 'password', self::credentials('grace@example.test'));
        $owner   = $sessions->reauthenticate($signedIn->record, 'password', self::credentials());

        self::assertSame([FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS, true], [$wrong->reason, $foreign->reason, $owner->isIssued()]);
        self::assertSame([true, false, false, true], $box->endedEarly);
        self::assertCount(2, $box->waits);
        self::assertGreaterThan(0, min($box->waits));
    }

    /**
     * An identity deactivated since the sign-in is refused once its correct
     * password has verified, when the session is admitted again under the lock:
     * the result and `AuthenticationFailed` (flow `reauthentication`, about
     * that identity) say `identity_inactive`, no proof is recorded, and the
     * attempt's slots stay counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityDeactivatedSinceTheSignInIsRefusedUnderTheLock(): void
    {
        $signedIn = $this->signedIn();

        DB::table('integration_identities')->update(['is_active' => false]);

        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class]);

        $result  = $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials());
        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FailureReason::IDENTITY_INACTIVE, null], [$result->reason, $result->accessToken]);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(
            [AuthenticationFlow::REAUTHENTICATION, FailureReason::IDENTITY_INACTIVE, $signedIn->identity->getAuthIdentifier(), $signedIn->record->getKey()],
            [$failure->flow, $failure->reason, $failure->context->identity?->getAuthIdentifier(), $failure->context->session?->getSessionIdentifier()],
        );
        self::assertSame(0, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
        self::assertSame(
            [1, 1],
            [self::counterHits('sign_in', 'per_account', AccountAttempts::account($signedIn->identity)), self::counterHits('api', 'sign_in', 'per_ip', self::CLIENT_IP)],
        );
    }

    /**
     * A session whose idle deadline passes while its credential is checked is
     * judged at the time its lock is taken, not when the reauthentication
     * began: it is refused as expired, and nothing is recorded or issued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatEndsDuringTheCheckIsFoundEndedUnderTheLock(): void
    {
        $signedIn = $this->signedIn();
        $deadline = $signedIn->record->getIdleExpiresAt();
        $moved    = false;

        self::assertNotNull($deadline);

        DB::listen(function (QueryExecuted $query) use (&$moved, $deadline): void {
            if ($moved || !str_contains($query->sql, 'integration_identities')) {
                return;
            }

            $moved = true;

            $this->clockAt(CarbonImmutable::instance($deadline));
        });

        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class]);

        $result = $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials());

        self::assertTrue($moved);
        self::assertSame([FailureReason::SESSION_EXPIRED, null], [$result->reason, $result->accessToken]);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(0, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
    }

    /**
     * A session acting as a membership in a tenant is reauthenticated with a
     * token that names the tenant the principal acts within.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationForATenantPrincipalCarriesItsTenant(): void
    {
        [, , $tenant] = $this->seedMember();

        $signedIn = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($signedIn);

        $result = $this->sessions('members')->reauthenticate($signedIn->record, 'password', self::credentials('member@example.test'));
        $claims = Auth::manager()->jwt('members')->parse((string) $result->accessToken, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $claims['tenant_id'] ?? null);
    }

    /**
     * Inside an application's transaction, `Reauthenticated` waits for the
     * commit and is never reported when the transaction rolls back, with the
     * proof it reports.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReauthenticatedWaitsForTheCommit(): void
    {
        $signedIn = $this->signedIn();

        $this->recordEvents([Reauthenticated::class]);

        DB::transaction(function () use ($signedIn): void {
            self::assertTrue($this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials())->isIssued());
            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([Reauthenticated::class], $this->recordedClasses());

        $this->recordEvents([Reauthenticated::class]);

        DB::beginTransaction();

        self::assertTrue($this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials())->isIssued());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
    }

    /**
     * A session revoked after its credential was checked, before the proof is
     * recorded, is found revoked under the lock: nothing is recorded or issued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionRevokedDuringTheCheckIsFoundUnderTheLock(): void
    {
        $signedIn = $this->signedIn();
        $revoked  = false;

        DB::listen(function (QueryExecuted $query) use (&$revoked, $signedIn): void {
            if ($revoked || !str_contains($query->sql, 'integration_identities')) {
                return;
            }

            $revoked = true;

            DB::table('authentication_sessions')->where('id', $signedIn->record->getKey())->update(['revoked_at' => $this->now]);
        });

        $result = $this->sessions()->reauthenticate($signedIn->record, 'password', self::credentials());

        self::assertTrue($revoked);
        self::assertSame(FailureReason::SESSION_REVOKED, $result->reason);
        self::assertSame(0, SessionProof::query()->where('kind', 'first_factor_reauthentication')->count());
    }

    /**
     * Configure the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * A session the identity signed in to with its password now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The session's refresh state and deadlines, as stored.
     *
     * @return array<string, mixed>
     */
    private static function refreshState(): array
    {
        $columns = ['refresh_key', 'previous_refresh_key', 'refresh_rotated_at', 'signed_in_at', 'idle_expires_at', 'absolute_expires_at', 'revoked_at', 'principal_id'];

        return array_intersect_key(Session::query()->sole()->getAttributes(), array_flip($columns));
    }

    /**
     * Give the guards a credential timebox with a real budget that records
     * whether each check cut it short, instead of sleeping.
     *
     * @return \Tests\Fixtures\Passwords\RecordingTimebox
     */
    private function recordingTimebox(): RecordingTimebox
    {
        $box = new RecordingTimebox;

        config()->set('authentication.timebox.credentials_microseconds', self::BUDGET);
        app()->instance(Timebox::class, $box);

        return $box;
    }

    /**
     * Move the clocks to the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }
}
