<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
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
 * Feature tests of reauthenticating a session with a result an external
 * identity provider verified.
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
     * A reauthentication through the session's own link renews its
     * authentication time only.
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

        $result = $this->sessions()->reauthenticateExternally(
            $signedIn->record->getKey(),
            $this->throughTheLink(authenticatedAt: $this->now->addMinutes(59)),
            self::requestClient(),
        );

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
     * A reauthentication keeps the provider context the session began with.
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

        self::assertTrue($this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $through, self::requestClient())->isIssued());
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
     * A redemption is reported after `Reauthenticated`, and a refused one
     * reports none.
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

        self::assertTrue($this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $through, self::requestClient())->isIssued());
        self::assertSame([Reauthenticated::class, ExternalResultRedeemed::class], $this->recordedClasses());

        $redeemed = $this->recordedEvent(ExternalResultRedeemed::class);

        self::assertSame(AuthenticationFlow::REAUTHENTICATION, $redeemed->flow);
        self::assertSame(['external_provider', 'connection-7', 'request-5'], [$redeemed->context->method, $redeemed->context->connectionId, $redeemed->context->requestReference]);
        EventContextAssertions::assertIdentity($signedIn->identity, $redeemed->context);
        EventContextAssertions::assertSession($signedIn->record, $redeemed->context);
        self::assertNull($this->recordedEvent(Reauthenticated::class)->context->connectionId);

        $this->recordEvents([Reauthenticated::class, ExternalResultRedeemed::class, AuthenticationFailed::class]);

        $through = new ExternalResult('connection-7', self::ISSUER, 'subject-1', requestReference: 'request-6');
        $refused = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $through, self::requestClient());

        self::assertSame(FailureReason::PROOF_INVALID, $refused->reason);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(
            ['connection-7', 'request-6'],
            [$this->recordedEvent(AuthenticationFailed::class)->context->connectionId, $this->recordedEvent(AuthenticationFailed::class)->context->requestReference],
        );
    }

    /**
     * An external reauthentication reports the client given, never the guard's
     * request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalReauthenticationReportsTheClientGiven(): void
    {
        $signedIn = $this->signedInExternally();
        $client   = self::sameSiteClient();

        $this->clockAt($this->now->addHour());

        $sessions = self::sessionsOf($this->crossSiteGuard());

        $this->recordEvents([Reauthenticated::class, ExternalResultRedeemed::class, AuthenticationFailed::class]);

        $through = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now->addMinutes(59));

        self::assertTrue($sessions->reauthenticateExternally($signedIn->record->getKey(), $through, $client)->isIssued());
        self::assertSame($client, $this->recordedEvent(Reauthenticated::class)->context->client);
        self::assertSame($client, $this->recordedEvent(ExternalResultRedeemed::class)->context->client);

        $this->recordEvents([Reauthenticated::class, ExternalResultRedeemed::class, AuthenticationFailed::class]);

        self::assertFalse($sessions->reauthenticateExternally($signedIn->record->getKey(), new ExternalResult('connection-7', self::ISSUER, 'subject-1'), $client)->isIssued());
        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
    }

    /**
     * The `auth_time` becomes the later of the session's and the provider's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAuthenticationTimeIsTheLaterOfTheSessionsAndTheProviders(): void
    {
        $signedIn = $this->signedInExternally();

        $this->clockAt($this->now->addHour());

        $later = $this->sessions()->reauthenticateExternally(
            $signedIn->record->getKey(),
            $this->throughTheLink(authenticatedAt: $this->now->addMinutes(50)),
            self::requestClient(),
        );
        $older = $this->sessions()->reauthenticateExternally(
            $signedIn->record->getKey(),
            $this->throughTheLink(authenticatedAt: $this->now->addMinutes(10)),
            self::requestClient(),
        );

        self::assertSame($this->now->addMinutes(50)->getTimestamp(), self::authenticationOf($later)[0]);
        self::assertSame($this->now->addMinutes(50)->getTimestamp(), self::authenticationOf($older)[0]);

        $future = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now->addHours(2)), self::requestClient());

        self::assertSame($this->now->addHour()->getTimestamp(), self::authenticationOf($future)[0]);
        self::assertSame(3, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * Only evidence the evidence contract accepts adds to the `amr`.
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

        $unaccepted = $this->sessions()->reauthenticateExternally(
            $key,
            $this->throughTheLink(authenticatedAt: $this->now->addMinutes(30), evidence: $evidence),
            self::requestClient(),
        );

        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD], self::authenticationOf($unaccepted)[1]);
        self::assertNull(SessionProof::query()->where('kind', 'external_reauthentication')->sole()->getAttributes()['evidence']);

        $policy = new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR, RequirementKind::ADDITIONAL_VERIFICATION]);

        $this->app?->instance(ExternalEvidencePolicy::class, $policy);

        $accepted = $this->sessions()->reauthenticateExternally(
            $key,
            $this->throughTheLink(authenticatedAt: $this->now->addMinutes(40), evidence: $evidence),
            self::requestClient(),
        );
        $proof = SessionProof::query()->where('kind', 'external_reauthentication')->orderByDesc('authenticated_at')->firstOrFail();

        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD, 'mfa'], self::authenticationOf($accepted)[1]);
        self::assertSame([true, true], [$proof->accepted, $proof->multifactor]);
        self::assertSame(['pwd', 'otp'], ExternalEvidence::fromStored($proof->evidence)?->methods);
        self::assertSame($signedIn->identity->getAuthIdentifier(), $policy->asked[0]['subject']->identity->getAuthIdentifier());
        self::assertSame(['api', 'connection-7'], [$policy->asked[0]['subject']->application, $policy->asked[0]['subject']->connectionId]);
    }

    /**
     * Only the link that established the session reauthenticates it.
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
            self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $result, self::requestClient())->reason);
        }

        $this->app?->instance(ExternalEvidencePolicy::class, $policy);

        $locks = 0;

        DB::listen(static function (QueryExecuted $query) use (&$locks): void {
            $locks += (int) (stripos($query->sql, 'for update') !== false);
        });

        $graces = $this->linkedResult($grace, 'connection-7', 'link-1', 'grace-subject', authenticatedAt: $this->now, evidence: new ExternalEvidence(['mfa'], null, $this->now));

        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $graces, self::requestClient())->reason);
        self::assertSame([], $policy->asked);
        self::assertSame(0, $locks);

        $reported = array_map(
            static fn (AuthenticationFailed $event): array => [$event->flow, $event->reason, $event->context->method, $event->context->identityId, $event->context->sessionId],
            $this->recordedAs(AuthenticationFailed::class),
        );

        $owner = IdentifierCoercion::stringify($identity->getAuthIdentifier());

        self::assertSame(
            [[AuthenticationFlow::REAUTHENTICATION, FailureReason::LINK_MISMATCH, 'external_provider', $owner, $signedIn->record->getKey()]],
            array_values(array_unique($reported, SORT_REGULAR)),
        );
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * A result naming another link is refused before anything is locked.
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

        self::assertSame(
            FailureReason::LINK_MISMATCH,
            $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $named('link-1-again'), self::requestClient())->reason,
        );
        self::assertSame(0, $locks);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());

        self::assertTrue($this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $named('link-1'), self::requestClient())->isIssued());
    }

    /**
     * A session no external provider established is never reauthenticated
     * through a link.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithNoLinkIsNeverReauthenticatedThroughOne(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $result = $this->linkedResult($identity, authenticatedAt: $this->now);

        self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($session->record->getKey(), $result, self::requestClient())->reason);
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

        $result = $this->sessions()->reauthenticateExternally(
            $signedIn->record->getKey(),
            new ExternalResult('connection-7', self::ISSUER, 'nobody', authenticatedAt: $this->now),
            self::requestClient(),
        );

        self::assertSame(FailureReason::EXTERNAL_RESULT_UNLINKED, $result->reason);
        self::assertSame([ExternalResultUnlinked::class, AuthenticationFailed::class], $this->recordedClasses());
        $unlinked = $this->recordedEvent(ExternalResultUnlinked::class);

        self::assertSame(['connection-7', self::ISSUER], [$unlinked->context->connectionId, $unlinked->issuer]);
    }

    /**
     * A disallowed method, or a result with no time, is refused.
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

        self::assertSame(
            FailureReason::PROOF_INVALID,
            $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink(), self::requestClient())->reason,
        );

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->reauthenticate($signedIn->record)->reason);
        self::assertInstanceOf(AuthenticationFailed::class, $this->recorded[1]);
        EventContextAssertions::assertSession(null, $this->recorded[1]->context);
        self::assertCount($asked, $this->externalLinks()->asked);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
    }

    /**
     * A provider time before the session began is recorded as given and leaves
     * the authentication time where it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProviderTimeBeforeTheSessionBeganLeavesTheAuthenticationTime(): void
    {
        $signedIn = $this->signedInExternally();
        $early    = $this->now->subSeconds(30);

        $this->clockAt($this->now->addSeconds(10));
        $this->recordEvents([Reauthenticated::class, AuthenticationFailed::class]);

        $result = $this->sessions()->reauthenticateExternally($signedIn->record->getKey(), $this->throughTheLink(authenticatedAt: $early), self::requestClient());

        self::assertTrue($result->isIssued());
        self::assertSame([$this->now->getTimestamp(), [FirstFactor::EXTERNAL_PROVIDER_METHOD]], self::authenticationOf($result));
        self::assertSame($early->getTimestamp(), SessionProof::query()->where('kind', 'external_reauthentication')->sole()->authenticated_at->getTimestamp());
        self::assertSame([Reauthenticated::class], $this->recordedClasses());
    }

    /**
     * A session that is not live takes no external reauthentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotLiveTakesNoReauthentication(): void
    {
        $signedIn = $this->signedInExternally();
        $admin    = $this->sessions('admin')->signInExternally($this->throughTheLink(), self::requestContext())->session;
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
            self::assertSame(
                FailureReason::SESSION_UNKNOWN,
                $this->sessions()->reauthenticateExternally($unknown, $this->throughTheLink(authenticatedAt: $this->now), self::requestClient())->reason,
            );
        }

        self::assertCount($asked, $this->externalLinks()->asked);
    }

    /**
     * What changes while the adapter holds the result is judged again under the
     * lock.
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
     * A session deleted meanwhile is `session_unknown`, reported for the
     * session given.
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
     * The tenant's policy is asked with the proof just recorded.
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

            self::assertSame(
                $reason,
                $this->sessions('members')->reauthenticateExternally($session->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now), self::requestClient())->reason,
            );
        }

        $principal = IdentifierCoercion::stringify($membership->getKey());
        $key       = IdentifierCoercion::stringify($session->record->getKey());

        self::assertSame(
            [[FailureReason::SSO_REQUIRED, $principal, $key], [FailureReason::ADDITIONAL_FACTOR_REQUIRED, $principal, $key]],
            array_map(
                static fn (AuthenticationFailed $event): array => [$event->reason, $event->context->principalId, $event->context->sessionId],
                $this->recordedAs(AuthenticationFailed::class),
            ),
        );

        DB::beginTransaction();

        $refused = $this->sessions('members')->reauthenticateExternally($session->record->getKey(), $this->throughTheLink(authenticatedAt: $this->now), self::requestClient());

        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $refused->reason);
        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());

        $this->app?->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $this->recordEvents([Reauthenticated::class]);

        $evidence = new ExternalEvidence(['mfa'], null, $this->now);
        $met      = $this->sessions('members')->reauthenticateExternally(
            $session->record->getKey(),
            $this->throughTheLink(authenticatedAt: $this->now, evidence: $evidence),
            self::requestClient(),
        );

        self::assertTrue($met->isIssued());
        self::assertSame(1, SessionProof::query()->where('kind', 'external_reauthentication')->count());

        $context = $this->recordedEvent(Reauthenticated::class)->context;

        self::assertSame(
            [IdentifierCoercion::stringify($member->getAuthIdentifier()), $principal, $key],
            [$context->identityId, $context->principalId, $context->sessionId],
        );
    }

    /**
     * The tenant's policy is judged on current reads under the row's lock.
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

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult> $results */
        $results = new \ArrayObject;
        $reads   = fn (?ExternalEvidence $evidence): array => self::statementsDuring(function () use ($session, $evidence, $results): void {
            $through = $this->throughTheLink(authenticatedAt: $this->now, evidence: $evidence);

            $results->append($this->sessions('members')->reauthenticateExternally($session->record->getKey(), $through, self::requestClient()));
        });

        $refused = array_values(array_filter($reads(null), self::readsProofs(...)));

        $this->app?->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $issued = array_values(array_filter($reads(new ExternalEvidence(['mfa'], null, $this->now)), self::readsProofs(...)));

        self::assertSame(
            [[FailureReason::ADDITIONAL_FACTOR_REQUIRED, false], [null, true]],
            array_map(static fn (AccessTokenResult $result): array => [$result->reason, $result->isIssued()], $results->getArrayCopy()),
        );
        self::assertSame(1, SessionProof::query()->where('kind', 'external_reauthentication')->count());
        self::assertStringContainsString('authentication_provenance', $refused[0]);
        self::assertStringContainsString('authentication_provenance', $refused[1]);
        self::assertSame([false, $locked, $locked, $locked, $locked], array_map(self::sharesLock(...), $refused));
        self::assertSame([false, $locked, $locked, $locked, $locked], array_map(self::sharesLock(...), $issued));
    }

    /**
     * Newer evidence accepted for less keeps the tenant's requirement met.
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
            self::requestClient(),
        );

        $proof = SessionProof::query()->where('kind', 'external_reauthentication')->sole();

        self::assertTrue($reauthenticated->isIssued());
        self::assertSame([true, false], [$proof->accepted, $proof->multifactor]);
    }

    /**
     * `Reauthenticated` waits for the adapter's commit and a rollback withdraws
     * it.
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
     * A session's standing holds only for the link that established it.
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
        $password = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

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
     * A standing inside a transaction reads the provenance current.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStandingUnderTheLockReadsTheProvenanceCurrent(): void
    {
        $signedIn = $this->signedInExternally();

        self::markSharedLocks();

        $key       = $signedIn->record->getKey();
        $standings = [];
        $ask       = fn (): ?FailureReason => $this->sessions()->externalStanding($key, $signedIn->identity, 'connection-7', 'link-1');

        self::assertSame([self::takesSharedLocks()], self::proofReadLocks(static function () use ($ask, &$standings): void {
            $standings[] = DB::transaction($ask);
        }));
        self::assertSame([false], self::proofReadLocks(static function () use ($ask, &$standings): void {
            $standings[] = $ask();
        }));
        self::assertSame([null, null], $standings);
    }

    /**
     * A session that is not live has no standing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotLiveHasNoStanding(): void
    {
        $signedIn = $this->signedInExternally();
        $admin    = $this->sessions('admin')->signInExternally($this->throughTheLink(), self::requestContext())->session;
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
     * A standing locks the session's row only inside a transaction.
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
     * The session's refresh token, deadlines and provenance.
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
     * Sign the seeded identity in through `link-1` of `connection-7`.
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
        $session  = $this->sessions()->signInExternally($result, self::requestContext())->session;

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
     * Reauthenticate the session through the seeded identity's link.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $session
     * @return \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult
     *
     * @throws \Throwable
     */
    private function reauthenticate(Model $session): AccessTokenResult
    {
        return $this->sessions()->reauthenticateExternally($session->getKey(), $this->throughTheLink(authenticatedAt: CarbonImmutable::now()), self::requestClient());
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
