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
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ProvesSessions;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
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
