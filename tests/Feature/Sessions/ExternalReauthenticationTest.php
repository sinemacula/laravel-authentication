<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SignsInExternally;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use SineMacula\Laravel\Authentication\Sessions\ExternalResults;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests of reauthenticating a session through `Auth::sessions()` with a
 * result an external identity provider verified: only through the very link
 * that established the session, a new access token whose `auth_time` is the
 * later of the session's and the provider's, nothing else renewed unless the
 * evidence contract accepts the provider's evidence, and every refusal answered
 * and reported, never thrown.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalReauthentication::class)]
#[CoversClass(ExternalResults::class)]
#[CoversTrait(SignsInExternally::class)]
final class ExternalReauthenticationTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
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
     * A reauthentication through the session's own link records an
     * `external_reauthentication` proof at the provider's time, with the
     * connection as its channel and no evaluation, and issues a new access
     * token only, whose `auth_time` is the provider's and whose `amr` is the
     * session's as it was; the session keeps its refresh token, deadlines and
     * provenance, and `Reauthenticated` reports it with `external_provider`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationThroughTheLinkRenewsTheAuthenticationTimeOnly(): void
    {
        $signedIn = $this->signedInExternally();
        $before   = self::sessionState();

        $this->clockAt($this->now->addHour());
        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class, ExternalResultUnlinked::class]);

        $result = $this->sessions()->reauthenticateExternally($signedIn->record, $this->throughTheLink(authenticatedAt: $this->now->addMinutes(59)));

        self::assertTrue($result->isIssued());
        self::assertSame($signedIn->record->getKey(), $result->session?->getKey());

        $proof = SessionProof::query()->where('kind', 'external_reauthentication')->sole();

        self::assertSame(
            ['reauthenticate', 'external_provider', 'external_provider', 'connection-7', [FirstFactor::EXTERNAL_PROVIDER_METHOD], null, null],
            [$proof->purpose, $proof->method, $proof->channel_kind, $proof->channel_reference, $proof->methods, $proof->accepted, $proof->multifactor],
        );
        self::assertSame($this->now->addMinutes(59)->getTimestamp(), $proof->authenticated_at->getTimestamp());
        self::assertSame([$this->now->addMinutes(59)->getTimestamp(), [FirstFactor::EXTERNAL_PROVIDER_METHOD]], self::authenticationOf($result));
        self::assertSame($before, self::sessionState());
        self::assertSame([Reauthenticated::class], $this->recordedClasses());
        $event = $this->recordedEvent(Reauthenticated::class);

        self::assertSame(['api', 'external_provider'], [$event->context->guard, $event->context->method]);
    }

    /**
     * `auth_time` becomes the later of the session's and the provider's: a
     * provider time older than the session's newest proof, but not before the
     * session began, is recorded and leaves `auth_time` where it was, and one
     * after now is recorded as now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAuthenticationTimeIsTheLaterOfTheSessionsAndTheProviders(): void
    {
        $signedIn = $this->signedInExternally();

        $this->clockAt($this->now->addHour());

        $later = $this->sessions()->reauthenticateExternally($signedIn->record, $this->throughTheLink(authenticatedAt: $this->now->addMinutes(50)));
        $older = $this->sessions()->reauthenticateExternally($signedIn->record, $this->throughTheLink(authenticatedAt: $this->now->addMinutes(10)));

        self::assertSame($this->now->addMinutes(50)->getTimestamp(), self::authenticationOf($later)[0]);
        self::assertSame($this->now->addMinutes(50)->getTimestamp(), self::authenticationOf($older)[0]);

        $future = $this->sessions()->reauthenticateExternally($signedIn->record, $this->throughTheLink(authenticatedAt: $this->now->addHours(2)));

        self::assertSame($this->now->addHour()->getTimestamp(), self::authenticationOf($future)[0]);
        self::assertSame(3, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * Evidence the evidence contract accepts as multifactor authentication is
     * recorded with the proof, whose evaluation is accepted and multifactor, so
     * the token's `amr` gains the provider's value again and `mfa`; evidence
     * the default contract judges records nothing and adds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAcceptedEvidenceAddsToTheAmr(): void
    {
        $signedIn = $this->signedInExternally();
        $evidence = new ExternalEvidence(['pwd', 'otp'], 'urn:example:acr:mfa', $this->now->addMinutes(30));

        $this->clockAt($this->now->addHour());

        $unaccepted = $this->sessions()->reauthenticateExternally($signedIn->record, $this->throughTheLink(authenticatedAt: $this->now->addMinutes(30), evidence: $evidence));

        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD], self::authenticationOf($unaccepted)[1]);
        self::assertNull(SessionProof::query()->where('kind', 'external_reauthentication')->sole()->getAttributes()['evidence']);

        $policy = new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR, RequirementKind::ADDITIONAL_VERIFICATION]);

        $this->app?->instance(ExternalEvidencePolicy::class, $policy);

        $accepted = $this->sessions()->reauthenticateExternally($signedIn->record, $this->throughTheLink(authenticatedAt: $this->now->addMinutes(40), evidence: $evidence));
        $proof    = SessionProof::query()->where('kind', 'external_reauthentication')->orderByDesc('authenticated_at')->firstOrFail();

        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD, 'mfa'], self::authenticationOf($accepted)[1]);
        self::assertSame([true, true], [$proof->accepted, $proof->multifactor]);
        self::assertSame(['pwd', 'otp'], ExternalEvidence::fromStored($proof->evidence)?->methods);
        self::assertSame($signedIn->identity->getAuthIdentifier(), $policy->asked[0]['subject']->identity->getAuthIdentifier());
        self::assertSame(['api', 'connection-7'], [$policy->asked[0]['subject']->application, $policy->asked[0]['subject']->connectionId]);
    }

    /**
     * Only the very link that established the session reauthenticates it:
     * another link of the same identity through the same connection, the same
     * subject through another connection, and a link that maps to another
     * identity are each `link_mismatch`, reported with the session, and record
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheLinkThatEstablishedTheSessionReauthenticatesIt(): void
    {
        $signedIn = $this->signedInExternally();
        $identity = $signedIn->identity;
        $grace    = $this->seedIdentity('grace@example.test');

        $this->recordEvents([AuthenticationFailed::class]);

        $results = [
            $this->linkedResult($identity, 'connection-7', 'link-2', 'second-subject', authenticatedAt: $this->now),
            $this->linkedResult($identity, 'connection-8', 'link-1', 'subject-1', authenticatedAt: $this->now),
            $this->linkedResult($grace, 'connection-7', 'link-1', 'grace-subject', authenticatedAt: $this->now),
        ];

        foreach ($results as $result) {
            self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($signedIn->record, $result)->reason);
        }

        $reported = array_map(
            static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason, $event->context->method, $event->context->sessionId],
            $this->recorded,
        );

        self::assertSame(
            [[AuthenticationFlow::REAUTHENTICATION, FailureReason::LINK_MISMATCH, 'external_provider', $signedIn->record->getKey()]],
            array_values(array_unique($reported, SORT_REGULAR)),
        );
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * A session no external provider established, so no link either, is never
     * reauthenticated through one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithNoLinkIsNeverReauthenticatedThroughOne(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $result = $this->linkedResult($identity, authenticatedAt: $this->now);

        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($session->record, $result)->reason);
    }

    /**
     * A result linked to no identity is reported with `ExternalResultUnlinked`
     * and refused as `external_result_unlinked`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnlinkedResultIsReportedAndRefused(): void
    {
        $signedIn = $this->signedInExternally();

        $this->recordEvents([ExternalResultUnlinked::class, AuthenticationFailed::class]);

        $result = $this->sessions()->reauthenticateExternally($signedIn->record, new ExternalResult('connection-7', self::ISSUER, 'nobody', authenticatedAt: $this->now));

        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $result->reason);
        self::assertSame([ExternalResultUnlinked::class, AuthenticationFailed::class], $this->recordedClasses());
        $unlinked = $this->recordedEvent(ExternalResultUnlinked::class);

        self::assertSame(['connection-7', self::ISSUER], [$unlinked->connectionId, $unlinked->issuer]);
    }

    /**
     * An application that does not allow `external_provider` refuses before the
     * session is read or the link contract asked; a result that does not say
     * when the provider authenticated the identity is `proof_invalid` before
     * the link contract is asked, and so is one timed before the session began.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatTheApplicationOrTheResultLacksIsRefused(): void
    {
        $signedIn = $this->signedInExternally();
        $asked    = count($this->externalLinks()->asked);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::PROOF_INVALID, $this->sessions()->reauthenticateExternally($signedIn->record, $this->throughTheLink())->reason);

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->reauthenticate($signedIn->record)->reason);
        self::assertInstanceOf(AuthenticationFailed::class, $this->recorded[1]);
        self::assertNull($this->recorded[1]->context->session);
        self::assertCount($asked, $this->externalLinks()->asked);

        config()->set('auth.guards.api.application', ['methods' => ['external_provider']]);

        $early = $this->throughTheLink(authenticatedAt: $this->now->subSecond());

        self::assertSame(FailureReason::PROOF_INVALID, $this->sessions()->reauthenticateExternally($signedIn->record, $early)->reason);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * A session that is another guard's, revoked, pending, ended, a machine's
     * or gone takes no external reauthentication, and the link contract is
     * never asked for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotLiveTakesNoReauthentication(): void
    {
        $signedIn = $this->signedInExternally();
        $admin    = $this->sessions('admin')->signInExternally($this->throughTheLink())->session;
        $key      = $signedIn->record->getKey();
        $asked    = count($this->externalLinks()->asked);

        self::assertNotNull($admin);
        self::assertSame(FailureReason::SESSION_GUARD_MISMATCH, $this->reauthenticate($admin->record)->reason);

        $states = [
            [['revoked_at' => $this->now], FailureReason::SESSION_REVOKED],
            [['revoked_at' => null, 'status' => 'pending'], FailureReason::SESSION_PENDING],
            [['status' => 'active', 'idle_expires_at' => $this->now], FailureReason::SESSION_EXPIRED],
            [['idle_expires_at' => $this->now->addHour(), 'authenticatable_type' => MachineClient::class], FailureReason::MACHINE_IDENTITY],
        ];

        foreach ($states as [$state, $reason]) {
            DB::table('authentication_sessions')->where('id', $key)->update($state);

            self::assertSame($reason, $this->reauthenticate($signedIn->record)->reason);
        }

        self::assertSame(FailureReason::SESSION_UNKNOWN, $this->reauthenticate(new Session)->reason);
        self::assertCount($asked, $this->externalLinks()->asked);
    }

    /**
     * What changes while the adapter holds the result is judged again under the
     * session's lock: a session revoked meanwhile is `session_revoked`, one
     * whose provenance now records another link `link_mismatch`, another
     * identity's session put under the key `link_mismatch`, and a new session
     * of the same identity under the key `session_unknown`, reported for the
     * session given. None records a proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatChangesMeanwhileIsJudgedUnderTheLock(): void
    {
        $signedIn = $this->signedInExternally();
        $key      = $signedIn->record->getKey();
        $session  = (array) DB::table('authentication_sessions')->where('id', $key)->sole();
        $grace    = IdentifierCoercion::stringify($this->seedIdentity('grace@example.test')->getKey());
        $changes  = [
            [['revoked_at' => $this->now], [], FailureReason::SESSION_REVOKED],
            [[], ['link_id' => 'link-2'], FailureReason::LINK_MISMATCH],
            [['authenticatable_id' => $grace], [], FailureReason::LINK_MISMATCH],
            [['generation' => 'another'], [], FailureReason::SESSION_UNKNOWN],
        ];

        $this->recordEvents([AuthenticationFailed::class]);

        foreach ($changes as [$row, $provenance, $reason]) {
            DB::table('authentication_sessions')->where('id', $key)->update($session);
            DB::table('authentication_provenance')->update(['link_id' => 'link-1']);

            $this->externalLinks()->whileAsked(static function () use ($key, $row, $provenance): void {
                DB::table('authentication_sessions')->where('id', $key)->update($row + ['updated_at' => CarbonImmutable::now()]);
                DB::table('authentication_provenance')->update($provenance + ['created_at' => CarbonImmutable::now()]);
            });

            self::assertSame($reason, $this->reauthenticate($signedIn->record)->reason);
        }

        self::assertInstanceOf(AuthenticationFailed::class, $this->recorded[3]);
        self::assertSame($key, $this->recorded[3]->context->sessionId);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * Inside the adapter's transaction `Reauthenticated` waits for the commit,
     * and a rollback withdraws it with the proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReauthenticatedFollowsTheAdaptersTransaction(): void
    {
        $signedIn = $this->signedInExternally();

        $this->recordEvents([Reauthenticated::class]);

        DB::beginTransaction();

        self::assertTrue($this->reauthenticate($signedIn->record)->isIssued());
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());

        DB::transaction(fn (): AccessTokenResult => $this->reauthenticate($signedIn->record));

        self::assertSame([Reauthenticated::class], $this->recordedClasses());
    }

    /**
     * A session's standing is answered under its row's lock inside the
     * adapter's transaction: `null` for this guard's live session through
     * exactly the identity, connection and link that established it, and
     * `link_mismatch` for another link, connection or identity, or for a
     * session no link established. Nothing is written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStandingIsTheSessionsOwnLinkOnly(): void
    {
        $signedIn = $this->signedInExternally();
        $identity = $signedIn->identity;
        $grace    = $this->seedIdentity('grace@example.test');
        $password = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($password);

        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class, ExternalResultUnlinked::class]);

        $standings = DB::transaction(fn (): array => [
            $this->sessions()->externalStanding($signedIn->record, $identity, 'connection-7', 'link-1'),
            $this->sessions()->externalStanding($signedIn->record, $identity, 'connection-7', 'link-2'),
            $this->sessions()->externalStanding($signedIn->record, $identity, 'connection-7', 'LINK-1'),
            $this->sessions()->externalStanding($signedIn->record, $identity, 'connection-8', 'link-1'),
            $this->sessions()->externalStanding($signedIn->record, $grace, 'connection-7', 'link-1'),
            $this->sessions()->externalStanding($password->record, $identity, 'connection-7', 'link-1'),
        ]);

        self::assertSame([null, ...array_fill(0, 5, FailureReason::LINK_MISMATCH)], $standings);
        self::assertSame([], $this->recorded);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * A session that is unknown, another guard's, revoked, pending, ended or a
     * machine's has no standing, and nor has any session on an application that
     * does not allow `external_provider`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotLiveHasNoStanding(): void
    {
        $signedIn = $this->signedInExternally();
        $admin    = $this->sessions('admin')->signInExternally($this->throughTheLink())->session;
        $key      = $signedIn->record->getKey();
        $standing = fn (Session $session): ?FailureReason => DB::transaction(
            fn (): ?FailureReason => $this->sessions()->externalStanding($session, $signedIn->identity, 'connection-7', 'link-1'),
        );

        self::assertNotNull($admin);
        self::assertSame(FailureReason::SESSION_UNKNOWN, $standing(new Session));
        self::assertSame(FailureReason::SESSION_GUARD_MISMATCH, $standing($admin->record));

        $states = [
            [['revoked_at' => $this->now], FailureReason::SESSION_REVOKED],
            [['revoked_at' => null, 'status' => 'pending'], FailureReason::SESSION_PENDING],
            [['status' => 'active', 'idle_expires_at' => $this->now], FailureReason::SESSION_EXPIRED],
            [['idle_expires_at' => $this->now->addHour(), 'authenticatable_type' => MachineClient::class], FailureReason::MACHINE_IDENTITY],
            [['authenticatable_type' => IntegrationIdentity::class], null],
        ];

        foreach ($states as [$state, $reason]) {
            DB::table('authentication_sessions')->where('id', $key)->update($state);

            self::assertSame($reason, $standing($signedIn->record));
        }

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $standing($signedIn->record));
    }

    /**
     * A standing locks the session's row until the transaction ends, so it is
     * asked only inside one: outside, it throws and reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStandingIsAskedOnlyInsideATransaction(): void
    {
        $signedIn = $this->signedInExternally();
        $queries  = 0;

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        try {
            $this->sessions()->externalStanding($signedIn->record, $signedIn->identity, 'connection-7', 'link-1');

            self::fail('A standing was answered outside a transaction.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith('An external session\'s standing is locked until the transaction ends', $exception->getMessage());
        }

        self::assertSame(0, $queries);
    }

    /**
     * Define the guards the tests sign in through.
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
     * The `auth_time` and `amr` of the access token a reauthentication issued.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult  $result
     * @return array{0: mixed, 1: mixed}
     */
    private static function authenticationOf(AccessTokenResult $result): array
    {
        $claims = Auth::manager()->jwt('api')->parse((string) $result->accessToken?->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);

        return [$claims['auth_time'] ?? null, $claims['amr'] ?? null];
    }

    /**
     * What a reauthentication must leave as it was: the session's refresh
     * token, deadlines and provenance.
     *
     * @return array<string, mixed>
     */
    private static function sessionState(): array
    {
        $columns = ['refresh_key', 'previous_refresh_key', 'refresh_rotated_at', 'signed_in_at', 'idle_expires_at', 'absolute_expires_at', 'revoked_at'];

        return [
            ...array_intersect_key(Session::query()->sole()->getAttributes(), array_flip($columns)),
            'provenance' => (array) DB::table('authentication_provenance')->sole(),
        ];
    }

    /**
     * Sign the seeded identity in through its link, `link-1` of `connection-7`,
     * authenticated at the provider now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedInExternally(): SignedInSession
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->now))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * A result through the seeded identity's link.
     *
     * @param  ?\Carbon\CarbonImmutable  $authenticatedAt
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     */
    private function throughTheLink(?CarbonImmutable $authenticatedAt = null, ?ExternalEvidence $evidence = null): ExternalResult
    {
        return new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $authenticatedAt, evidence: $evidence);
    }

    /**
     * Reauthenticate the session through the seeded identity's link, the
     * provider authenticating it now.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    private function reauthenticate(Session $session): AccessTokenResult
    {
        return $this->sessions()->reauthenticateExternally($session, $this->throughTheLink(authenticatedAt: CarbonImmutable::now()));
    }

    /**
     * Set every clock the tests read to the time given.
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
