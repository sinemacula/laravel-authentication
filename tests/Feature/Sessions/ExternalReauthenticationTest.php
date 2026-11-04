<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\ExternalResultRedeemed;
use SineMacula\Laravel\Authentication\Events\ExternalResultUnlinked;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SignsInExternally;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use SineMacula\Laravel\Authentication\Sessions\ExternalResults;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\External\MethodTrustingEvidencePolicy;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
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
#[CoversClass(ProofIssuance::class)]
#[CoversTrait(SignsInExternally::class)]
final class ExternalReauthenticationTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions, MarksSharedLocks;

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

        $result = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now->addMinutes(59)));

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
     * A reauthentication whose result carries another provider context leaves
     * the one the session was established with as it was, and reports neither
     * on its events.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationKeepsTheProviderContextTheSessionBeganWith(): void
    {
        $signedIn = $this->signedInExternally(new ProviderContext(['protocol' => 'saml-6c1f']));
        $before   = self::sessionState();

        $this->clockAt($this->now->addHour());
        $this->recordEvents([Reauthenticated::class, ExternalResultRedeemed::class]);

        $other   = new ProviderContext(['protocol' => 'oidc-9e2a']);
        $through = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now->addMinutes(59), providerContext: $other);

        self::assertTrue($this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $through)->isIssued());
        self::assertSame($before, self::sessionState());
        self::assertSame(['protocol' => 'saml-6c1f'], SessionProofs::provenance($signedIn->record)?->providerContext?->toArray());
        self::assertSame([Reauthenticated::class, ExternalResultRedeemed::class], $this->recordedClasses());

        foreach ([Reauthenticated::class, ExternalResultRedeemed::class] as $class) {
            $reported = serialize($this->recordedEvent($class));

            self::assertStringNotContainsString('saml-6c1f', $reported);
            self::assertStringNotContainsString('oidc-9e2a', $reported);
        }
    }

    /**
     * A reauthentication reports `ExternalResultRedeemed` (flow
     * `reauthentication`) after `Reauthenticated`, naming the session, the
     * connection and the request reference; a refused one names both on its
     * `AuthenticationFailed`, and reports no redemption.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARedemptionIsReportedAfterTheReauthentication(): void
    {
        $signedIn = $this->signedInExternally();

        $this->clockAt($this->now->addHour());
        $this->recordEvents([Reauthenticated::class, ExternalResultRedeemed::class, AuthenticationFailed::class]);

        $through = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now->addMinutes(59), requestReference: 'request-5');

        self::assertTrue($this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $through)->isIssued());
        self::assertSame([Reauthenticated::class, ExternalResultRedeemed::class], $this->recordedClasses());

        $redeemed = $this->recordedEvent(ExternalResultRedeemed::class);

        self::assertSame(AuthenticationFlow::REAUTHENTICATION, $redeemed->flow);
        self::assertSame(['external_provider', 'connection-7', 'request-5'], [$redeemed->context->method, $redeemed->context->connectionId, $redeemed->context->requestReference]);
        EventContextAssertions::assertIdentity($signedIn->identity, $redeemed->context);
        EventContextAssertions::assertSession($signedIn->record, $redeemed->context);
        self::assertNull($this->recordedEvent(Reauthenticated::class)->context->connectionId);

        $this->recordEvents([Reauthenticated::class, ExternalResultRedeemed::class, AuthenticationFailed::class]);

        $through = new ExternalResult('connection-7', self::ISSUER, 'subject-1', requestReference: 'request-6');
        $refused = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $through);

        self::assertSame(FailureReason::PROOF_INVALID, $refused->reason);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(
            ['connection-7', 'request-6'],
            [$this->recordedEvent(AuthenticationFailed::class)->context->connectionId, $this->recordedEvent(AuthenticationFailed::class)->context->requestReference],
        );
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

        $later = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now->addMinutes(50)));
        $older = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now->addMinutes(10)));

        self::assertSame($this->now->addMinutes(50)->getTimestamp(), self::authenticationOf($later)[0]);
        self::assertSame($this->now->addMinutes(50)->getTimestamp(), self::authenticationOf($older)[0]);

        $future = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now->addHours(2)));

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
        $key      = $signedIn->record->getKey();
        $evidence = new ExternalEvidence(['pwd', 'otp'], 'urn:example:acr:mfa', $this->now->addMinutes(30));

        $this->clockAt($this->now->addHour());

        $unaccepted = $this->sessions()->reauthenticateExternally($key, $this->throughTheLink(authenticatedAt: $this->now->addMinutes(30), evidence: $evidence));

        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD], self::authenticationOf($unaccepted)[1]);
        self::assertNull(SessionProof::query()->where('kind', 'external_reauthentication')->sole()->getAttributes()['evidence']);

        $policy = new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR, RequirementKind::ADDITIONAL_VERIFICATION]);

        $this->app?->instance(ExternalEvidencePolicy::class, $policy);

        $accepted = $this->sessions()->reauthenticateExternally($key, $this->throughTheLink(authenticatedAt: $this->now->addMinutes(40), evidence: $evidence));
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
     * nothing. A link to another identity is refused before anything is locked,
     * so the evidence that identity's result brings is never judged.
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
        $policy   = new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]);

        $this->recordEvents([AuthenticationFailed::class]);

        $results = [
            $this->linkedResult($identity, 'connection-7', 'link-2', 'second-subject', authenticatedAt: $this->now),
            $this->linkedResult($identity, 'connection-8', 'link-1', 'subject-1', authenticatedAt: $this->now),
        ];

        foreach ($results as $result) {
            self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $result)->reason);
        }

        $this->app?->instance(ExternalEvidencePolicy::class, $policy);

        $locks = 0;

        DB::listen(static function (QueryExecuted $query) use (&$locks): void {
            $locks += (int) (stripos($query->sql, 'for update') !== false);
        });

        $graces = $this->linkedResult($grace, 'connection-7', 'link-1', 'grace-subject', authenticatedAt: $this->now, evidence: new ExternalEvidence(['mfa'], null, $this->now));

        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $graces)->reason);
        self::assertSame([], $policy->asked);
        self::assertSame(0, $locks);

        $reported = array_map(
            static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason, $event->context->method, $event->context->identityId, $event->context->sessionId],
            $this->recorded,
        );

        $owner = IdentifierCoercion::stringify($identity->getAuthIdentifier());

        self::assertSame(
            [[AuthenticationFlow::REAUTHENTICATION, FailureReason::LINK_MISMATCH, 'external_provider', $owner, $signedIn->record->getKey()]],
            array_values(array_unique($reported, SORT_REGULAR)),
        );
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * A result that names a link the contract does not answer with (the
     * session's link removed and made again since) is `link_mismatch` before
     * anything is locked, recording nothing; one naming the session's own link
     * reauthenticates it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResultNamingAnotherLinkIsRefusedBeforeAnyLock(): void
    {
        $signedIn = $this->signedInExternally();
        $at       = CarbonImmutable::now();
        $named    = static fn (string $linkId): ExternalResult => new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $at, linkId: $linkId);
        $locks    = 0;

        DB::listen(static function (QueryExecuted $query) use (&$locks): void {
            $locks += (int) (stripos($query->sql, 'for update') !== false);
        });

        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $named('link-1-again'))->reason);
        self::assertSame(0, $locks);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());

        self::assertTrue($this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $named('link-1'))->isIssued());
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

        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($session->record->getKey(), $result)->reason);
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

        $result = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), new ExternalResult('connection-7', self::ISSUER, 'nobody', authenticatedAt: $this->now));

        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $result->reason);
        self::assertSame([ExternalResultUnlinked::class, AuthenticationFailed::class], $this->recordedClasses());
        $unlinked = $this->recordedEvent(ExternalResultUnlinked::class);

        self::assertSame(['connection-7', self::ISSUER], [$unlinked->context->connectionId, $unlinked->issuer]);
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

        self::assertSame(FailureReason::PROOF_INVALID, $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink())->reason);

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->reauthenticate($signedIn->record)->reason);
        self::assertInstanceOf(AuthenticationFailed::class, $this->recorded[1]);
        EventContextAssertions::assertSession(null, $this->recorded[1]->context);
        self::assertCount($asked, $this->externalLinks()->asked);

        config()->set('auth.guards.api.application', ['methods' => ['external_provider']]);

        $early = $this->throughTheLink(authenticatedAt: $this->now->subSecond());

        self::assertSame(FailureReason::PROOF_INVALID, $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $early)->reason);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * A session that is another guard's, revoked, pending, ended or a machine's
     * takes no external reauthentication, nor does an identifier that names no
     * session or cannot be a key, and the link contract is never asked for
     * them. A machine's session that is also revoked is refused as revoked: the
     * session's own refusal comes before its owner's.
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
            [['revoked_at' => $this->now], FailureReason::SESSION_REVOKED],
        ];

        foreach ($states as [$state, $reason]) {
            DB::table('authentication_sessions')->where('id', $key)->update($state);

            self::assertSame($reason, $this->reauthenticate($signedIn->record)->reason);
        }

        foreach ([(string) Str::uuid7(), 'not-a-key', null] as $unknown) {
            self::assertSame(FailureReason::SESSION_UNKNOWN, $this->sessions()->reauthenticateExternally($unknown, $this->throughTheLink(authenticatedAt: $this->now))->reason);
        }

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
            [['generation' => Str::uuid7()->toString()], [], FailureReason::SESSION_UNKNOWN],
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
     * A session deleted while the adapter holds the result is gone when its row
     * is locked: `session_unknown`, reported for the session given, and nothing
     * recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionDeletedMeanwhileIsReportedForTheSessionGiven(): void
    {
        $signedIn = $this->signedInExternally();
        $key      = $signedIn->record->getKey();

        $this->recordEvents([AuthenticationFailed::class]);

        $this->externalLinks()->whileAsked(static function () use ($key): void {
            DB::table('authentication_sessions')->where('id', $key)->delete();
        });

        self::assertSame(FailureReason::SESSION_UNKNOWN, $this->reauthenticate($signedIn->record)->reason);
        self::assertSame($key, $this->recordedEvent(AuthenticationFailed::class)->context->sessionId);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * The session is judged against its tenant's authentication policy with the
     * proof just recorded among its own: a tenant that no longer admits the
     * connection is `sso_required`, one that now requires a further factor the
     * session does not meet `additional_factor_required`, each reported with
     * the session and its principal and recording nothing, inside the adapter's
     * transaction too, which goes on, and the row is left as it was; evidence
     * this very reauthentication brings, once accepted, meets that factor, and
     * the token is issued, reported for the member, the principal and the
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantsPolicyIsAskedWithTheProofRecorded(): void
    {
        [$member, $membership] = $this->seedMember();

        $policy  = new ScriptedTenantAuthenticationPolicy;
        $session = $this->sessions('members')->signInExternally($this->linkedResult($member, subject: 'subject-1'), self::asPrincipal($membership))->session;
        $row     = (array) DB::table('authentication_sessions')->sole();

        self::assertNotNull($session);

        $this->app?->instance(TenantAuthenticationPolicy::class, $policy);
        $this->recordEvents([AuthenticationFailed::class]);

        $refusals = [
            [new TenantRequirement('v2', connections: ['connection-8']), FailureReason::SSO_REQUIRED],
            [new TenantRequirement('v3', new Requirement(multifactor: new RequirementPart)), FailureReason::ADDITIONAL_FACTOR_REQUIRED],
        ];

        foreach ($refusals as [$requirement, $reason]) {
            $policy->requirement = $requirement;

            self::assertSame($reason, $this->sessions('members')->reauthenticateExternally($session->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now))->reason);
        }

        $principal = IdentifierCoercion::stringify($membership->getKey());
        $key       = IdentifierCoercion::stringify($session->record->getKey());

        self::assertSame(
            [[FailureReason::SSO_REQUIRED, $principal, $key], [FailureReason::ADDITIONAL_FACTOR_REQUIRED, $principal, $key]],
            array_map(static fn (AuthenticationFailed $event): array => [$event->reason, $event->context->principalId, $event->context->sessionId], $this->recorded),
        );

        DB::beginTransaction();

        $refused = $this->sessions('members')->reauthenticateExternally($session->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now));

        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $refused->reason);
        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());

        $this->app?->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $this->recordEvents([Reauthenticated::class]);

        $evidence = new ExternalEvidence(['mfa'], null, $this->now);
        $met      = $this->sessions('members')->reauthenticateExternally($session->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now, evidence: $evidence));

        self::assertTrue($met->isIssued());
        self::assertSame(1, SessionProof::query()->where('kind', 'external_reauthentication')->count());

        $context = $this->recordedEvent(Reauthenticated::class)->context;

        self::assertSame(
            [IdentifierCoercion::stringify($member->getAuthIdentifier()), $principal, $key],
            [$context->identityId, $context->principalId, $context->sessionId],
        );
    }

    /**
     * A reauthentication judges the session against its tenant's policy under
     * the row's lock, with the proof it recorded, so every read of the
     * session's provenance and proofs that judgement makes takes a shared lock
     * where the engine takes one: the connection, the first factor, the
     * accepted evidence and the check's proofs, whether it then refuses or
     * issues. The link's check before it reads the provenance plainly, and the
     * issuance reads the proofs current, as it always does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantsPolicyIsJudgedOnCurrentReads(): void
    {
        [$member, $membership] = $this->seedMember();

        $session = $this->sessions('members')->signInExternally($this->linkedResult($member, subject: 'subject-1'), self::asPrincipal($membership))->session;

        self::assertNotNull($session);

        $requirement = new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart), ['connection-7']);

        $this->app?->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy($requirement));
        $this->app?->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        self::markSharedLocks();

        $locked = self::takesSharedLocks();
        $reads  = fn (?ExternalEvidence $evidence): array => self::statementsDuring(function () use ($session, $evidence): void {
            $this->sessions('members')->reauthenticateExternally($session->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now, evidence: $evidence));
        });

        $refused = array_values(array_filter($reads(null), self::readsProofs(...)));

        $this->app?->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $issued = array_values(array_filter($reads(new ExternalEvidence(['mfa'], null, $this->now)), self::readsProofs(...)));

        self::assertSame(1, SessionProof::query()->where('kind', 'external_reauthentication')->count());
        self::assertStringContainsString('authentication_provenance', $refused[0]);
        self::assertStringContainsString('authentication_provenance', $refused[1]);
        self::assertSame([false, $locked, $locked, $locked, $locked], array_map(self::sharesLock(...), $refused));
        self::assertSame([false, $locked, $locked, $locked, $locked], array_map(self::sharesLock(...), $issued));
    }

    /**
     * A reauthentication bringing evidence the evidence contract accepts only
     * for less than the tenant requires is issued, as one bringing no evidence
     * is: the multifactor evidence the session signed in with still meets the
     * tenant's requirement, though the newer evidence does not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNewerEvidenceAcceptedForLessKeepsTheTenantsRequirementMet(): void
    {
        [$member, $membership] = $this->seedMember();

        $this->app?->instance(ExternalEvidencePolicy::class, new MethodTrustingEvidencePolicy([
            'mfa' => [RequirementKind::MULTIFACTOR],
            'hwk' => [RequirementKind::PHISHING_RESISTANCE],
        ]));
        $requirement = new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart));

        $this->app?->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy($requirement));

        $signedIn = $this->sessions('members')->signInExternally(
            $this->linkedResult($member, subject: 'subject-1', evidence: new ExternalEvidence(['mfa'], null, $this->now->subMinute())),
            self::asPrincipal($membership),
        );

        self::assertTrue($signedIn->isSignedIn());

        $session = $signedIn->session?->record;

        self::assertNotNull($session);

        $reauthenticated = $this->sessions('members')->reauthenticateExternally(
            $session->getKey(),
            $this->throughTheLink(authenticatedAt: $this->now, evidence: new ExternalEvidence(['hwk'], null, $this->now)),
        );

        $proof = SessionProof::query()->where('kind', 'external_reauthentication')->sole();

        self::assertTrue($reauthenticated->isIssued());
        self::assertSame([true, false], [$proof->accepted, $proof->multifactor]);
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
     * session no link established. With no link given, any link of that
     * connection stands, but a session recorded with no link still does not.
     * Nothing is written or reported.
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
            $this->sessions()->externalStanding($signedIn->record->getKey(), $identity, 'connection-7', 'link-1'),
            $this->sessions()->externalStanding($signedIn->record->getKey(), $identity, 'connection-7', 'link-2'),
            $this->sessions()->externalStanding($signedIn->record->getKey(), $identity, 'connection-7', 'LINK-1'),
            $this->sessions()->externalStanding($signedIn->record->getKey(), $identity, 'connection-8', 'link-1'),
            $this->sessions()->externalStanding($signedIn->record->getKey(), $grace, 'connection-7', 'link-1'),
            $this->sessions()->externalStanding($password->record->getKey(), $identity, 'connection-7', 'link-1'),
            $this->sessions()->externalStanding($signedIn->record->getKey(), $identity, 'connection-7'),
            $this->sessions()->externalStanding($signedIn->record->getKey(), $identity, 'connection-8'),
            $this->sessions()->externalStanding($signedIn->record->getKey(), $grace, 'connection-7'),
            $this->sessions()->externalStanding($password->record->getKey(), $identity, 'connection-7'),
        ]);

        self::assertSame([null, ...array_fill(0, 5, FailureReason::LINK_MISMATCH), null, ...array_fill(0, 3, FailureReason::LINK_MISMATCH)], $standings);

        DB::table('authentication_provenance')->update(['link_id' => null]);

        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->externalStanding($signedIn->record->getKey(), $identity, 'connection-7'));
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
        $standing = fn (mixed $sessionId): ?FailureReason => DB::transaction(
            fn (): ?FailureReason => $this->sessions()->externalStanding($sessionId, $signedIn->identity, 'connection-7', 'link-1'),
        );

        self::assertNotNull($admin);
        self::assertSame([FailureReason::SESSION_UNKNOWN, FailureReason::SESSION_UNKNOWN], [$standing((string) Str::uuid7()), $standing('not-a-key')]);
        self::assertSame(FailureReason::SESSION_GUARD_MISMATCH, $standing($admin->record->getKey()));

        $states = [
            [['revoked_at' => $this->now], FailureReason::SESSION_REVOKED],
            [['revoked_at' => null, 'status' => 'pending'], FailureReason::SESSION_PENDING],
            [['status' => 'active', 'idle_expires_at' => $this->now], FailureReason::SESSION_EXPIRED],
            [['idle_expires_at' => $this->now->addHour(), 'authenticatable_type' => MachineClient::class], FailureReason::MACHINE_IDENTITY],
            [['authenticatable_type' => IntegrationIdentity::class], null],
        ];

        foreach ($states as [$state, $reason]) {
            DB::table('authentication_sessions')->where('id', $key)->update($state);

            self::assertSame($reason, $standing($key));
        }

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $standing($key));
    }

    /**
     * A standing asked inside a transaction locks the session's row until the
     * transaction ends; asked outside one, as when a reauthentication flow
     * starts, it answers alike and locks nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStandingLocksTheSessionOnlyInsideATransaction(): void
    {
        $signedIn = $this->signedInExternally();
        $locks    = 0;

        DB::listen(static function (QueryExecuted $query) use (&$locks): void {
            $locks += (int) (stripos($query->sql, 'for update') !== false);
        });

        self::assertNull($this->sessions()->externalStanding($signedIn->record->getKey(), $signedIn->identity, 'connection-7'));
        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->externalStanding($signedIn->record->getKey(), $signedIn->identity, 'connection-7', 'link-2'));
        self::assertSame(0, $locks);
        self::assertNull(DB::transaction(fn (): ?FailureReason => $this->sessions()->externalStanding($signedIn->record->getKey(), $signedIn->identity, 'connection-7', 'link-1')));
        self::assertSame(DB::connection()->getDriverName() === 'sqlite' ? 0 : 1, $locks);
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
     * authenticated at the provider now, with the provider context given.
     *
     * @param  ?\SineMacula\Laravel\Authentication\External\ProviderContext  $providerContext
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedInExternally(?ProviderContext $providerContext = null): SignedInSession
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->now, providerContext: $providerContext);
        $session  = $this->sessions()->signInExternally($result)->session;

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
        return $this->sessions()->reauthenticateExternally($session->getKey(), $this->throughTheLink(authenticatedAt: CarbonImmutable::now()));
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
