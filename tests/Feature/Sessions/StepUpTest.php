<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SteppedUp;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ProofAcceptance;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ProvesSessions;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of stepping a session up with a further factor its adapter
 * verified, over HTTP behind `auth:api` and through the session service: a new
 * access token for the same session and nothing else, the proof recorded and
 * reported once committed, and every refusal of the proof or of the session
 * answered and reported, never thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionStepUp::class)]
#[CoversClass(ProofIssuance::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(AccessTokenResult::class)]
#[CoversClass(SteppedUp::class)]
#[CoversTrait(ProvesSessions::class)]
final class StepUpTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and register the routes.
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

        Route::middleware('auth:api')->post('/step-up', static function (Request $request): array {

            $identity = Auth::identity();
            $session  = Auth::session();

            assert($identity instanceof IntegrationIdentity && $session !== null);

            $purpose = Purpose::from($request->string('purpose', 'step_up')->toString());
            $result  = Auth::sessions('api')->stepUp(self::adapterProof(
                $identity,
                'api',
                $session->getSessionIdentifier(),
                $purpose,
                methods: [$request->string('method')->toString()],
            ));

            return ['access_token' => $result->accessToken, 'reason' => $result->reason?->value, 'expires_at' => $result->expiresAt?->getTimestamp()];
        });

        Route::middleware('auth:api')->get('/me', static fn (): array => ['session' => IdentifierCoercion::stringify(Auth::session()?->getSessionIdentifier())]);
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
     * Stepping up through a route behind `auth:api` answers a new access token
     * for the same session, which authenticates, as the one before it still
     * does until it expires; the session keeps its refresh token, deadlines and
     * row, and its refresh token still refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpOverHttpIssuesANewAccessTokenOnly(): void
    {
        $signedIn = $this->signedIn();
        $before   = self::refreshState();

        $this->clockAt($this->now->addMinute());

        $answer = $this->withToken($signedIn->tokens->accessToken)->postJson('/step-up', ['method' => 'otp'])->assertOk()->json();

        self::assertIsArray($answer);
        self::assertNull($answer['reason']);
        self::assertIsString($answer['access_token']);
        self::assertNotSame($signedIn->tokens->accessToken, $answer['access_token']);
        self::assertSame($before, self::refreshState());

        $key = IdentifierCoercion::stringify($signedIn->record->getKey());

        $this->bearer($answer['access_token'])->assertOk()->assertExactJson(['session' => $key]);
        $this->bearer($signedIn->tokens->accessToken)->assertOk()->assertExactJson(['session' => $key]);

        self::assertTrue($this->sessions()->refresh($signedIn->tokens->refreshToken)->isRefreshed());
    }

    /**
     * A step-up records the proof on the session for `step_up`, bound to its
     * owner and guard, with the adapter's evaluation, and the new token's
     * expiry; `SteppedUp` reports it with the proof's kind and method once
     * committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpRecordsTheProofAndReportsIt(): void
    {
        $signedIn = $this->signedIn();

        $this->recordEvents([SteppedUp::class, AuthenticationFailed::class]);
        $this->clockAt($this->now->addMinute());

        $proof = self::adapterProof(
            $signedIn->identity,
            'api',
            $signedIn->record->getKey(),
            kind: ProofKind::RECOVERY_CODE,
            evaluation: new Evaluation(true, false),
            methods: ['kba'],
        );
        $result = $this->sessions()->stepUp($proof);

        self::assertTrue($result->isIssued());
        self::assertSame($signedIn->record->getKey(), $result->session?->getKey());

        $claims = Auth::manager()->jwt('api')->parse((string) $result->accessToken, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame($claims['exp'], $result->expiresAt?->getTimestamp());

        $stored = SessionProof::query()->where('kind', 'recovery_code')->sole();

        self::assertSame(
            [Purpose::STEP_UP->value, 'totp', 'factor-1', ['kba'], true, false],
            [$stored->purpose, $stored->method, $stored->factor_reference, $stored->methods, $stored->accepted, $stored->multifactor],
        );
        self::assertSame(
            [IntegrationIdentity::class, IdentifierCoercion::stringify($signedIn->identity->getAuthIdentifier()), 'api'],
            [$stored->authenticatable_type, $stored->authenticatable_id, $stored->guard],
        );
        self::assertSame($this->now->addMinute()->getTimestamp(), $stored->authenticated_at->getTimestamp());
        self::assertSame([SteppedUp::class], $this->recordedClasses());

        $event = $this->recordedEvent(SteppedUp::class);

        self::assertSame(ProofKind::RECOVERY_CODE, $event->kind);
        self::assertSame(
            ['api', 'totp', IdentifierCoercion::stringify($signedIn->record->getKey())],
            [$event->context->guard, $event->context->method, $event->context->sessionId],
        );

        // The identity reported is the session's owner as admitted again under
        // the lock, not the instance the adapter bound the proof to.
        $reported = $event->context()->identity;

        self::assertInstanceOf(IntegrationIdentity::class, $reported);
        self::assertNotSame($signedIn->identity, $reported);
        self::assertSame($signedIn->identity->getAuthIdentifier(), $reported->getAuthIdentifier());
    }

    /**
     * The new access token's `auth_time` is the step-up's, and its `amr` gains
     * the proof's values, and `mfa` only when the evaluation reports
     * multifactor authentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNewTokensClaimsComeFromTheProofs(): void
    {
        $signedIn = $this->signedIn();

        $this->clockAt($this->now->addMinute());

        $single = $this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), evaluation: new Evaluation(true, false), methods: ['otp']));

        self::assertSame([$this->now->addMinute()->getTimestamp(), ['pwd', 'otp']], self::authentication((string) $single->accessToken));

        $this->clockAt($this->now->addMinutes(2));

        $multi = $this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), methods: ['hwk']));

        self::assertSame([$this->now->addMinutes(2)->getTimestamp(), ['pwd', 'otp', 'hwk', 'mfa']], self::authentication((string) $multi->accessToken));
    }

    /**
     * A refresh and a switch of principal after a step-up carry the session's
     * authentication as it stands and never renew it: each new access token's
     * `auth_time` is the step-up's, ten minutes before its own issue time, and
     * its `amr` keeps the step-up's values and `mfa`. Each names the tenant its
     * principal acts within: the refreshed token the first membership's, and
     * the switched token the tenant of the membership switched to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshAndASwitchKeepTheStepUpsAuthentication(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $signedIn = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($signedIn);

        $steppedUpAt = $this->now->addMinutes(10);
        $issuedAt    = $this->now->addMinutes(20);

        $this->clockAt($steppedUpAt);

        self::assertTrue($this->sessions('members')->stepUp(self::adapterProof($member, 'members', $signedIn->record->getKey()))->isIssued());

        $this->clockAt($issuedAt);

        $refreshed = $this->sessions('members')->refresh($signedIn->tokens->refreshToken)->session;

        self::assertNotNull($refreshed);

        $switched = $this->sessions('members')->switchPrincipal($refreshed->tokens->refreshToken, $second)->session;

        self::assertNotNull($switched);

        foreach ([[$refreshed, $tenant], [$switched, $other]] as [$carried, $actingWithin]) {
            $claims = Auth::manager()->jwt('members')->parse($carried->tokens->accessToken, TokenType::ACCESS);

            self::assertIsArray($claims);
            self::assertSame(
                [$steppedUpAt->getTimestamp(), ['pwd', 'otp', 'mfa'], $issuedAt->getTimestamp(), IdentifierCoercion::stringify($actingWithin->getKey())],
                [$claims['auth_time'] ?? null, $claims['amr'] ?? null, $claims['iat'] ?? null, $claims['tenant_id'] ?? null],
            );
        }
    }

    /**
     * Rows of `[time zone]`: zones behind and ahead of the application's.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideProofZones(): iterable
    {
        yield from [
            'behind the application'   => ['America/New_York'],
            'ahead of the application' => ['Asia/Tokyo'],
        ];
    }

    /**
     * A proof time an adapter reports in a time zone other than the
     * application's is recorded as the same instant: the new token's
     * `auth_time` is that instant, and the proof meets a freshness requirement
     * straight away.
     *
     * @param  string  $zone
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideProofZones')]
    public function testAProofTimedInAnyTimeZoneIsRecordedAsItsInstant(string $zone): void
    {
        $signedIn = $this->signedIn();
        $at       = $this->now->addMinute();

        $this->clockAt($at);

        $result = $this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), at: $at->setTimezone($zone)));
        $newest = SessionProofs::newestMeeting($signedIn->record, new FreshnessRequirement(60, [ProofKind::ADDITIONAL_FACTOR]), $at);

        self::assertTrue($result->isIssued());
        self::assertSame($at->getTimestamp(), SessionProof::query()->where('kind', 'additional_factor')->sole()->authenticated_at->getTimestamp());
        self::assertSame($at->getTimestamp(), self::authentication((string) $result->accessToken)[0]);
        self::assertSame($at->getTimestamp(), $newest?->authenticatedAt->getTimestamp());
    }

    /**
     * Rows of `[changes, reason]`: every proof a step-up refuses, as what
     * differs from one it takes (a further factor made now by the session's
     * owner, on its guard, for it and `step_up`, accepted).
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedProofs(): iterable
    {
        $invalid = FailureReason::PROOF_INVALID;
        $binding = FailureReason::PROOF_BINDING_MISMATCH;

        yield from [
            'a first factor'                  => [['kind' => ProofKind::FIRST_FACTOR], $invalid],
            'a first-factor reauthentication' => [['kind' => ProofKind::FIRST_FACTOR_REAUTHENTICATION], $invalid],
            'an external reauthentication'    => [['kind' => ProofKind::EXTERNAL_REAUTHENTICATION], $invalid],
            'a sign-in purpose'               => [['purpose' => Purpose::SIGN_IN], $invalid],
            'a reauthentication purpose'      => [['purpose' => Purpose::REAUTHENTICATE], $invalid],
            'an evaluation not accepted'      => [['evaluation' => new Evaluation(false, true)], $invalid],
            'a time after now'                => [['offset' => 1], $invalid],
            'a time before the sign-in'       => [['offset' => -61], $invalid],
            'another identity'                => [['identity' => 'other'], $binding],
            'another application'             => [['application' => 'admin'], $binding],
        ];
    }

    /**
     * A proof the step-up does not take is refused with its reason, reported by
     * `AuthenticationFailed` (flow `step_up`), records nothing, issues nothing
     * and reports no step-up.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedProofs')]
    public function testAStepUpRefusesAProofItDoesNotTake(array $changes, FailureReason $reason): void
    {
        $signedIn = $this->signedIn();
        $now      = $this->now->addMinute();

        $this->clockAt($now);
        $this->recordEvents([SteppedUp::class, AuthenticationFailed::class]);

        $kind       = $changes['kind']       ?? ProofKind::ADDITIONAL_FACTOR;
        $purpose    = $changes['purpose']    ?? Purpose::STEP_UP;
        $evaluation = $changes['evaluation'] ?? new Evaluation(true, true);
        $offset     = $changes['offset']     ?? 0;
        $identity   = ($changes['identity'] ?? 'same') === 'other' ? $this->seedIdentity('grace@example.test') : $signedIn->identity;

        self::assertInstanceOf(ProofKind::class, $kind);
        self::assertInstanceOf(Purpose::class, $purpose);
        self::assertInstanceOf(Evaluation::class, $evaluation);
        self::assertIsInt($offset);

        $application = $changes['application'] ?? 'api';

        self::assertIsString($application);

        $proof = self::adapterProof($identity, $application, $signedIn->record->getKey(), $purpose, $kind, $now->addSeconds($offset), $evaluation);

        $this->assertRefused($this->sessions()->stepUp($proof), $reason);
    }

    /**
     * A proof bound to another session of the same identity cannot step this
     * one up: it steps up the one it names, or none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofBoundToAnotherSessionStepsOnlyThatOneUp(): void
    {
        $first  = $this->signedIn();
        $second = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($second);

        $this->clockAt($this->now->addMinute());

        $result = $this->sessions()->stepUp(self::adapterProof($first->identity, 'api', $second->record->getKey()));

        self::assertSame($second->record->getKey(), $result->session?->getKey());
        self::assertSame(1, SessionProof::query()->where('session_id', $second->record->getKey())->where('kind', 'additional_factor')->count());
        self::assertSame(0, SessionProof::query()->where('session_id', $first->record->getKey())->where('kind', 'additional_factor')->count());
    }

    /**
     * Rows of what makes the session a step-up names unable to take one, and
     * the reason.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedSessions(): iterable
    {
        yield from [
            'no such session'      => ['unknown', FailureReason::SESSION_UNKNOWN],
            'a malformed key'      => ['malformed', FailureReason::SESSION_UNKNOWN],
            'revoked'              => ['revoked', FailureReason::SESSION_REVOKED],
            'ended'                => ['ended', FailureReason::SESSION_EXPIRED],
            'another guard\'s'     => ['admin', FailureReason::SESSION_GUARD_MISMATCH],
            'an inactive identity' => ['inactive', FailureReason::IDENTITY_INACTIVE],
            'a disallowed method'  => ['method', FailureReason::METHOD_NOT_ALLOWED],
            'a machine\'s'         => ['machine', FailureReason::MACHINE_IDENTITY],
            'another principal\'s' => ['principal', FailureReason::SESSION_PRINCIPAL_MISMATCH],
        ];
    }

    /**
     * A session that is gone, not this guard's live session, owned by a
     * machine, acting as a principal it no longer resolves to, or whose
     * identity or method no longer passes, takes no step-up, whatever the
     * proof.
     *
     * @param  string  $state
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedSessions')]
    public function testASessionThatCannotTakeAStepUpRefusesIt(string $state, FailureReason $reason): void
    {
        $signedIn = $state === 'admin' ? $this->signedIn('admin') : $this->signedIn();
        $key      = match ($state) {
            'unknown'   => '0190e1a4-0000-7000-8000-000000000001',
            'malformed' => 'not-a-key',
            default     => $signedIn->record->getKey(),
        };

        $this->putInto($state);

        $this->recordEvents([SteppedUp::class, AuthenticationFailed::class]);

        $this->assertRefused($this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $key)), $reason);
    }

    /**
     * A proof made in the very second the session signed in steps it up: the
     * proof is measured from the session's own start, not from now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofMadeAsTheSessionStartedStepsItUp(): void
    {
        $signedIn = $this->signedIn();

        $this->clockAt($this->now->addMinute());

        $result = $this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), at: $this->now));

        self::assertTrue($result->isIssued());
        self::assertSame($this->now->getTimestamp(), SessionProof::query()->where('kind', 'additional_factor')->sole()->authenticated_at->getTimestamp());
    }

    /**
     * The new access token never outlives its session: when the session ends
     * before the access lifetime does, the token and the result expire with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNewTokenExpiresNoLaterThanItsSession(): void
    {
        $signedIn = $this->signedIn();
        $ends     = $this->now->addSeconds(90);

        DB::table('authentication_sessions')->update(['idle_expires_at' => $ends]);

        $result = $this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()));
        $claims = Auth::manager()->jwt('api')->parse((string) $result->accessToken, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame([$ends->getTimestamp(), $ends->getTimestamp()], [$claims['exp'], $result->expiresAt?->getTimestamp()]);
    }

    /**
     * A session acting as a membership in a tenant is stepped up with a token
     * that names the tenant the principal acts within.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpForATenantPrincipalCarriesItsTenant(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $signedIn = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($signedIn);

        $result = $this->sessions('members')->stepUp(self::adapterProof($member, 'members', $signedIn->record->getKey()));
        $claims = Auth::manager()->jwt('members')->parse((string) $result->accessToken, TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $claims['tenant_id'] ?? null);
    }

    /**
     * Inside an application's transaction, `SteppedUp` waits for the commit and
     * is never reported when the transaction rolls back, with the proof it
     * reports.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSteppedUpWaitsForTheCommit(): void
    {
        $signedIn = $this->signedIn();

        $this->recordEvents([SteppedUp::class]);

        DB::transaction(function () use ($signedIn): void {
            self::assertTrue($this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()))->isIssued());
            self::assertSame([], $this->recordedClasses());
        });

        self::assertSame([SteppedUp::class], $this->recordedClasses());

        $this->recordEvents([SteppedUp::class]);

        DB::beginTransaction();

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()))->isIssued());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, SessionProof::query()->where('kind', 'additional_factor')->count());
    }

    /**
     * A step-up over a route answers its refusal in its result, and issues
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedStepUpOverHttpAnswersItsReason(): void
    {
        $signedIn = $this->signedIn();

        $answer = $this->withToken($signedIn->tokens->accessToken)->postJson('/step-up', ['method' => 'otp', 'purpose' => 'sign_in'])->assertOk()->json();

        self::assertSame(['access_token' => null, 'reason' => 'proof_invalid', 'expires_at' => null], $answer);
        self::assertSame(0, SessionProof::query()->where('kind', 'additional_factor')->count());
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
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api'): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions($guard)->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Put the session, its identity or its guard into the state named.
     *
     * @param  string  $state
     * @return void
     */
    private function putInto(string $state): void
    {
        match ($state) {
            'revoked'   => DB::table('authentication_sessions')->update(['revoked_at' => $this->now]),
            'ended'     => DB::table('authentication_sessions')->update(['idle_expires_at' => $this->now]),
            'inactive'  => DB::table('integration_identities')->update(['is_active' => false]),
            'method'    => config()->set('auth.guards.api.application.methods', ['sso']),
            'machine'   => DB::table('authentication_sessions')->update(['authenticatable_type' => MachineClient::class]),
            'principal' => DB::table('authentication_sessions')->update(['principal_type' => 'another-model']),
            default     => null,
        };
    }

    /**
     * Assert the step-up was refused with the reason, reported by one
     * `AuthenticationFailed` (flow `step_up`) naming the method the proof was
     * verified with, with no proof recorded beyond the first factor and no
     * step-up reported.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult  $result
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function assertRefused(AccessTokenResult $result, FailureReason $reason): void
    {
        self::assertTrue($result->isFailed());
        self::assertSame($reason, $result->reason);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::STEP_UP, $reason, 'totp'], [$failure->flow, $failure->reason, $failure->context->method]);
        self::assertSame(0, SessionProof::query()->where('purpose', 'step_up')->count());
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
     * The `auth_time` and `amr` the access token carries.
     *
     * @param  string  $token
     * @return array{0: mixed, 1: mixed}
     */
    private static function authentication(#[\SensitiveParameter] string $token): array
    {
        $claims = Auth::manager()->jwt('api')->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);

        return [$claims['auth_time'] ?? null, $claims['amr'] ?? null];
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withToken($token)->getJson('/me');
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
