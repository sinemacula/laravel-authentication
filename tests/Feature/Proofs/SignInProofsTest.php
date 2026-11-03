<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ProofAcceptance;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\ExternalSignIn;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the proofs a sign-in records on its session: the first
 * factor a password sign-in verified, the one `start()` records, the provider's
 * an external sign-in records, the provenance itself, the further factor a
 * pending sign-in is completed with and every refusal of one, a choice of
 * principal carrying the first factor and provenance across, and the fresh
 * proofs of a session that replaces another.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(ExternalSignIn::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(SessionWriter::class)]
#[CoversClass(PendingSessions::class)]
#[CoversClass(ProofWriter::class)]
#[CoversClass(ProofAcceptance::class)]
#[CoversClass(SignInProof::class)]
#[CoversClass(NewProof::class)]
#[CoversClass(SessionProof::class)]
#[CoversClass(SessionProvenance::class)]
final class SignInProofsTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, whose sign-ins wait for a choice of principal. */
    private const string CHOOSERS = 'choosers';

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
     * A password sign-in records one proof on its new session: the first
     * factor, for `sign_in`, through the `password` method over a password
     * channel with no reference, nothing observed and no evaluation, standing
     * for `pwd`, timed at the sign-in, and bound to the identity, the guard and
     * the session's key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordSignInRecordsItsFirstFactor(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(1, $proofs);

        $proof = $proofs[0];

        self::assertSame([ProofKind::FIRST_FACTOR->value, Purpose::SIGN_IN->value, 'password'], [$proof->kind, $proof->purpose, $proof->method]);
        self::assertSame([ChannelKind::PASSWORD->value, null, null], [$proof->channel_kind, $proof->channel_reference, $proof->factor_reference]);
        self::assertSame(
            [null, null, null, null, null, null],
            [$proof->user_presence, $proof->user_verification, $proof->backup_eligible, $proof->backup_state, $proof->phishing_resistant, $proof->key_protection],
        );
        self::assertSame([null, null], [$proof->accepted, $proof->multifactor]);
        self::assertSame(['pwd'], $proof->methods);
        self::assertSame([IntegrationIdentity::class, (string) $identity->id, 'api'], [$proof->authenticatable_type, $proof->authenticatable_id, $proof->guard]);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $proof->session_id);
        self::assertSame($this->now->getTimestamp(), $proof->authenticated_at->getTimestamp());
        self::assertNull($proof->voided_at);
        self::assertNull(self::provenanceOf($session->record));
    }

    /**
     * A session's proofs are hidden from its serialised form: a code proof's
     * destination and the factor an adapter used are personal data.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofHidesItsReferencesWhenSerialised(): void
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $serialised = self::proofsOf($session->record)[0]->toArray();

        self::assertArrayNotHasKey('channel_reference', $serialised);
        self::assertArrayNotHasKey('factor_reference', $serialised);
        self::assertSame('password', $serialised['method']);
    }

    /**
     * `start()` records a first factor the caller did not describe: under the
     * method it names, an unknown channel, no `amr` value, timed now, and no
     * provenance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRecordsAnUnattestedFirstFactor(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->start($identity, null, 'sso')->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(1, $proofs);
        self::assertSame(
            [ProofKind::FIRST_FACTOR->value, 'sso', ChannelKind::UNKNOWN->value, null],
            [$proofs[0]->kind, $proofs[0]->method, $proofs[0]->channel_kind, $proofs[0]->channel_reference],
        );
        self::assertSame([], $proofs[0]->methods);
        self::assertSame($this->now->getTimestamp(), $proofs[0]->authenticated_at->getTimestamp());
        self::assertNull(self::provenanceOf($session->record));
    }

    /**
     * An external sign-in records the provider's first factor (under
     * `external_provider`, the connection as an external-provider channel, the
     * private namespaced `amr` value, the provider's authentication time) and
     * the provenance of the result, with the link's id and no evidence; the
     * session's first access token says it authenticated when the provider did,
     * two minutes before the token was issued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalSignInRecordsTheProvidersFirstFactorAndProvenance(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, 'connection-7', 'link-9', null, 'tenant-3', $this->now->subMinutes(2), $this->now->addHours(8), 'enforcement-12');
        $session  = $this->sessions()->signInExternally($result)->session;

        self::assertNotNull($session);
        self::assertSame('external_provider', $session->record->getSignInMethod());

        $proofs = self::proofsOf($session->record);

        self::assertCount(1, $proofs);
        self::assertSame('external_provider', $proofs[0]->method);
        self::assertSame([ChannelKind::EXTERNAL_PROVIDER->value, 'connection-7'], [$proofs[0]->channel_kind, $proofs[0]->channel_reference]);
        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD], $proofs[0]->methods);
        self::assertSame('urn:sinemacula:amr:external_provider', FirstFactor::EXTERNAL_PROVIDER_METHOD);
        self::assertSame($this->now->subMinutes(2)->getTimestamp(), $proofs[0]->authenticated_at->getTimestamp());

        $stored = self::provenanceOf($session->record);

        self::assertNotNull($stored);
        self::assertSame(['connection-7', 'tenant-3', 'enforcement-12', 'link-9'], [$stored->connection_id, $stored->tenant_id, $stored->policy_version, $stored->link_id]);
        self::assertSame($this->now->subMinutes(2)->getTimestamp(), $stored->provider_authenticated_at?->getTimestamp());
        self::assertSame($this->now->addHours(8)->getTimestamp(), $stored->provider_session_expires_at?->getTimestamp());
        self::assertNull($stored->accepted_evidence);
        self::assertSame($this->now->getTimestamp(), $stored->created_at->getTimestamp());
        self::assertArrayNotHasKey('accepted_evidence', $stored->toArray());

        $claims = Auth::manager()->jwt('api')->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame(
            [$this->now->subMinutes(2)->getTimestamp(), [FirstFactor::EXTERNAL_PROVIDER_METHOD], $this->now->getTimestamp()],
            [$claims['auth_time'] ?? null, $claims['amr'] ?? null, $claims['iat'] ?? null],
        );
    }

    /**
     * A provider authentication time after now is recorded as now, since the
     * clocks disagree, and a provenance without one is timed now; neither
     * changes the provenance's own record of what the provider said.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProviderTimeAfterNowOrNoneIsRecordedAsNow(): void
    {
        $identity = $this->seedIdentity();
        $future   = $this->sessions()->signInExternally($this->linkedResult($identity, authenticatedAt: $this->now->addMinute()))->session;
        $none     = $this->sessions()->signInExternally($this->linkedResult($identity))->session;

        self::assertNotNull($future);
        self::assertNotNull($none);
        self::assertSame($this->now->getTimestamp(), self::proofsOf($future->record)[0]->authenticated_at->getTimestamp());
        self::assertSame($this->now->addMinute()->getTimestamp(), self::provenanceOf($future->record)?->provider_authenticated_at?->getTimestamp());
        self::assertSame($this->now->getTimestamp(), self::proofsOf($none->record)[0]->authenticated_at->getTimestamp());
        self::assertNull(self::provenanceOf($none->record)?->provider_authenticated_at);
        self::assertNull(self::provenanceOf($none->record)?->tenant_id);
    }

    /**
     * The provider's deadline for its session caps the session's absolute
     * deadline below the application's limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProvidersDeadlineCapsTheSession(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity, sessionNotAfter: $this->now->addHours(8)))->session;

        self::assertNotNull($session);
        self::assertSame($this->now->addHours(8)->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * Rows of `[hours from now to the context's own deadline, hours from now to
     * the deadline the session is capped at]`, with the provider's deadline 8
     * hours from now.
     *
     * @return iterable<string, array{0: int, 1: int}>
     */
    public static function provideContextDeadlines(): iterable
    {
        yield from [
            'the context earlier' => [2, 2],
            'the context later'   => [10, 8],
        ];
    }

    /**
     * Of the provider's deadline and the context's own, the earlier caps the
     * session, and the provenance still records the provider's as it was given.
     *
     * @param  int  $contextIn
     * @param  int  $cappedIn
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideContextDeadlines')]
    public function testTheEarlierOfTheProvidersAndTheContextsDeadlinesApplies(int $contextIn, int $cappedIn): void
    {
        $identity = $this->seedIdentity();
        $context  = new SignInContext(new ClientContext('203.0.113.7', 'agent'), notAfter: $this->now->addHours($contextIn));
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity, sessionNotAfter: $this->now->addHours(8)), $context)->session;

        self::assertNotNull($session);
        self::assertSame($this->now->addHours($cappedIn)->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addHours(8)->getTimestamp(), self::provenanceOf($session->record)?->provider_session_expires_at?->getTimestamp());
    }

    /**
     * A provider whose deadline is this second or has passed starts no session:
     * the sign-in is refused as `session_expired`, reported by
     * `AuthenticationFailed`, before any session, proof or provenance is
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvidersPassedDeadlineIsRefusedBeforeAnythingIsWritten(): void
    {
        $identity = $this->seedIdentity();

        foreach ([$this->now, $this->now->subMinute()] as $deadline) {

            $this->recordEvents([AuthenticationFailed::class]);

            $result = $this->sessions()->signInExternally($this->linkedResult($identity, sessionNotAfter: $deadline));

            self::assertTrue($result->isFailed());
            self::assertSame(FailureReason::SESSION_EXPIRED, $result->reason);
            self::assertSame(FailureReason::SESSION_EXPIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        }

        self::assertSame(0, Session::query()->count());
        self::assertSame(0, SessionProof::query()->count());
        self::assertSame(0, SessionProvenance::query()->count());
    }

    /**
     * Rows of `[time zone]`: zones behind and ahead of the application's.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideDeadlineZones(): iterable
    {
        yield from [
            'behind the application'   => ['America/New_York'],
            'ahead of the application' => ['Asia/Tokyo'],
        ];
    }

    /**
     * A provider's deadline given in a time zone other than the application's
     * is kept to the same instant while the session waits for a further factor,
     * so the session ends exactly then once it activates.
     *
     * @param  string  $zone
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeadlineZones')]
    public function testAPendingFactorKeepsTheDeadlineInAnyTimeZone(string $zone): void
    {
        $identity = $this->seedIdentity();
        $deadline = $this->now->addHours(8)->setTimezone($zone);

        self::requireAFurtherFactor();

        [$pending, $credential] = self::pendingOf($this->sessions()->signInExternally($this->linkedResult($identity, sessionNotAfter: $deadline)));

        self::assertSame($deadline->getTimestamp(), Session::query()->sole()->getAbsoluteExpiresAt()?->getTimestamp());

        $this->clockAt($this->now->addMinutes(2));

        $session = $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN))->session;

        self::assertNotNull($session);
        self::assertSame($deadline->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * A provider's deadline given in a time zone other than the application's
     * is kept to the same instant while the session waits for a choice of
     * principal, so the session the choice activates ends exactly then.
     *
     * @param  string  $zone
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeadlineZones')]
    public function testAChoiceKeepsTheDeadlineInAnyTimeZone(string $zone): void
    {
        [$member, $membership] = $this->seedChooser();

        $deadline = $this->now->addHours(8)->setTimezone($zone);

        [, $credential] = self::pendingOf($this->sessions(self::CHOOSERS)->signInExternally($this->linkedResult($member, sessionNotAfter: $deadline)));

        $this->clockAt($this->now->addMinutes(2));

        $session = $this->sessions(self::CHOOSERS)->choose($credential, $membership)->session;

        self::assertNotNull($session);
        self::assertSame($deadline->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * The provider's times given in a time zone other than the application's
     * are recorded as the same instants when an external sign-in starts at
     * once: the provenance's authentication time and deadline, the first
     * factor's time, the session's absolute deadline and its access token's
     * `auth_time`.
     *
     * @param  string  $zone
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeadlineZones')]
    public function testAnImmediateStartKeepsTheProvidersTimesInAnyTimeZone(string $zone): void
    {
        $identity      = $this->seedIdentity();
        $authenticated = $this->now->subMinutes(5)->setTimezone($zone);
        $deadline      = $this->now->addHours(8)->setTimezone($zone);
        $session       = $this->sessions()->signInExternally($this->linkedResult($identity, authenticatedAt: $authenticated, sessionNotAfter: $deadline))->session;

        self::assertNotNull($session);

        $stored = self::provenanceOf($session->record);

        self::assertNotNull($stored);
        self::assertSame(
            [$authenticated->getTimestamp(), $deadline->getTimestamp()],
            [$stored->provider_authenticated_at?->getTimestamp(), $stored->provider_session_expires_at?->getTimestamp()],
        );
        self::assertSame($authenticated->getTimestamp(), self::proofsOf($session->record)[0]->authenticated_at->getTimestamp());
        self::assertSame($deadline->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());

        $claims = Auth::manager()->jwt('api')->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertSame($authenticated->getTimestamp(), $claims['auth_time'] ?? null);
    }

    /**
     * A sign-in that replaces the session the client proved it holds is a new
     * session with its own first factor; the replaced session keeps its own
     * proofs, and nothing is copied across.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASupersedingSignInStartsAFreshSetOfProofs(): void
    {
        $this->seedIdentity();

        $first = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($first);

        $this->clockAt($this->now->addHour());

        $context = SignInContext::fromRequest(app('request'), refreshToken: $first->tokens->refreshToken?->reveal());
        $second  = $this->sessions()->signIn('password', self::credentials(), $context)->session;

        self::assertNotNull($second);
        self::assertSame('superseded', Session::query()->whereKey($first->record->getKey())->value('revoked_reason'));
        self::assertCount(1, self::proofsOf($first->record));
        self::assertSame($this->now->getTimestamp(), self::proofsOf($first->record)[0]->authenticated_at->getTimestamp());
        self::assertCount(1, self::proofsOf($second->record));
        self::assertSame($this->now->addHour()->getTimestamp(), self::proofsOf($second->record)[0]->authenticated_at->getTimestamp());
    }

    /**
     * A provenance whose insert a model event cancels fails the sign-in with a
     * `LogicException`, and rolls back the session and its first factor with
     * it, so none of them is left behind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancelledProvenanceRollsBackTheSessionAndItsProofs(): void
    {
        $identity = $this->seedIdentity();

        SessionProvenance::creating(static fn (): bool => false);

        try {
            $this->sessions()->signInExternally($this->linkedResult($identity));
            self::fail('Expected a cancelled provenance to fail the sign-in.');
        } catch (\LogicException $exception) {
            self::assertSame(SessionProvenance::class . ' was not saved: a model event cancelled it, so the session it belongs to is not written.', $exception->getMessage());
        } finally {
            SessionProvenance::flushEventListeners();
        }

        self::assertSame(0, Session::query()->count());
        self::assertSame(0, SessionProof::query()->count());
        self::assertSame(0, SessionProvenance::query()->count());
    }

    /**
     * A proof whose insert a model event cancels fails the sign-in and rolls
     * the session back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACancelledProofRollsBackTheSession(): void
    {
        $this->seedIdentity();

        SessionProof::creating(static fn (): bool => false);

        try {
            $this->sessions()->signIn('password', self::credentials());
            self::fail('Expected a cancelled proof to fail the sign-in.');
        } catch (\LogicException $exception) {
            self::assertSame(SessionProof::class . ' was not saved: a model event cancelled it, so the session it belongs to is not written.', $exception->getMessage());
        } finally {
            SessionProof::flushEventListeners();
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * A pending session records its first factor when it is written, timed when
     * the credentials were verified, and keeps it, unchanged, when the session
     * activates later; the credential's digest is never shown.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionRecordsItsFirstFactorAtItsOwnTime(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        [$pending, $credential] = self::pendingOf($this->sessions()->signIn('password', self::credentials()));

        $row = Session::query()->sole();

        self::assertSame($pending->id, $row->getKey());
        self::assertArrayNotHasKey('pending_key', $row->toArray());
        self::assertArrayNotHasKey('attempt_windows', $row->toArray());
        self::assertCount(1, self::proofsOf($row));

        $this->clockAt($this->now->addMinutes(3));

        $session = $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN))->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(2, $proofs);
        self::assertSame([ProofKind::FIRST_FACTOR->value, ChannelKind::PASSWORD->value, ['pwd']], [$proofs[0]->kind, $proofs[0]->channel_kind, $proofs[0]->methods]);
        self::assertSame($this->now->getTimestamp(), $proofs[0]->authenticated_at->getTimestamp());
    }

    /**
     * A pending session satisfied with the further factor its adapter verified
     * records it beside the first factor, with its kind, method, channel,
     * factor, evaluation, `amr` values and time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSatisfyingRecordsTheFurtherFactor(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        [$pending, $credential] = self::pendingOf($this->sessions()->signIn('password', self::credentials()));

        $this->clockAt($this->now->addMinute());

        $proof   = self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN, ProofKind::RECOVERY_CODE, evaluation: new Evaluation(true, false), methods: ['otp', 'kba']);
        $session = $this->sessions()->satisfy($credential, $proof)->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(2, $proofs);
        self::assertSame(ProofKind::FIRST_FACTOR->value, $proofs[0]->kind);

        $recorded = $proofs[1];

        self::assertSame([ProofKind::RECOVERY_CODE->value, Purpose::SIGN_IN->value, 'totp'], [$recorded->kind, $recorded->purpose, $recorded->method]);
        self::assertSame([ChannelKind::AUTHENTICATOR_APP->value, 'factor-1'], [$recorded->channel_kind, $recorded->factor_reference]);
        self::assertSame([true, false], [$recorded->accepted, $recorded->multifactor]);
        self::assertSame(['otp', 'kba'], $recorded->methods);
        self::assertSame([IntegrationIdentity::class, (string) $identity->id, 'api'], [$recorded->authenticatable_type, $recorded->authenticatable_id, $recorded->guard]);
        self::assertSame($this->now->addMinute()->getTimestamp(), $recorded->authenticated_at->getTimestamp());
    }

    /**
     * An additional verification, the recovery-code fallback and multifactor
     * authentication stay apart: a recovery code satisfies the session as a
     * recovery code, never an additional factor, the check sees its kind and
     * evaluation as recorded, and the token's `amr` carries its own values and
     * `mfa` only once an accepted evaluation reports multifactor
     * authentication, never because two factors were used.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAdditionalVerificationRecoveryCodesAndMultifactorStayApart(): void
    {
        $identity = $this->seedIdentity();
        $check    = new ProofJudgingRequirementCheck;

        self::requireAFurtherFactor();

        app()->instance(RequirementCheck::class, $check);

        [$pending, $credential] = self::pendingOf($this->sessions()->signIn('password', self::credentials()));

        $this->clockAt($this->now->addMinute());

        $proof   = self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN, ProofKind::RECOVERY_CODE, evaluation: new Evaluation(true, false), methods: ['kba']);
        $session = $this->sessions()->satisfy($credential, $proof)->session;

        self::assertNotNull($session);

        $judged = end($check->judged);

        self::assertNotFalse($judged);

        [$recovery] = $judged->proofs(null, [ProofKind::RECOVERY_CODE, ProofKind::ADDITIONAL_FACTOR]);

        self::assertSame(ProofKind::RECOVERY_CODE, $recovery->kind);
        self::assertEquals(new Evaluation(true, false), $recovery->evaluation);
        self::assertSame([], $judged->proofs(null, [ProofKind::ADDITIONAL_FACTOR]));
        self::assertSame(['pwd', 'kba'], self::amrOf($session->tokens->accessToken->reveal()));

        $this->clockAt($this->now->addMinute());

        $single = $this->sessions()->stepUp(self::adapterProof($identity, 'api', $pending->id, evaluation: new Evaluation(true, false), methods: ['otp']));

        self::assertSame(['pwd', 'kba', 'otp'], self::amrOf((string) $single->accessToken?->reveal()));

        $this->clockAt($this->now->addMinute());

        $multi = $this->sessions()->stepUp(self::adapterProof($identity, 'api', $pending->id, evaluation: new Evaluation(true, true), methods: ['otp']));

        self::assertSame(['pwd', 'kba', 'otp', 'mfa'], self::amrOf((string) $multi->accessToken?->reveal()));
    }

    /**
     * The further factor that confirms a factor enrolled while the session
     * waited (purpose `enrollment`) satisfies it as any further factor does,
     * and is recorded with that purpose.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABootstrapEnrollmentsConfirmingFactorSatisfiesTheSession(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        [$pending, $credential] = self::pendingOf($this->sessions()->signIn('password', self::credentials()));

        $this->clockAt($this->now->addMinute());

        $session = $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::ENROLLMENT))->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(2, $proofs);
        self::assertSame([ProofKind::FIRST_FACTOR->value, Purpose::SIGN_IN->value], [$proofs[0]->kind, $proofs[0]->purpose]);
        self::assertSame([ProofKind::ADDITIONAL_FACTOR->value, Purpose::ENROLLMENT->value], [$proofs[1]->kind, $proofs[1]->purpose]);
    }

    /**
     * Rows of `[changes, reason]`: every further factor a pending session
     * refuses, as what differs from one it takes (made now by the session's
     * identity, on its guard, for its id and `sign_in`, accepted): the kind,
     * the purpose, the evaluation, the seconds from now it was made at, and
     * whether it names another identity, application or session.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideRefusedProofs(): iterable
    {
        $invalid = FailureReason::PROOF_INVALID;
        $binding = FailureReason::PROOF_BINDING_MISMATCH;

        yield from [
            'a first factor'                    => [['kind' => ProofKind::FIRST_FACTOR], $invalid],
            'a first-factor reauthentication'   => [['kind' => ProofKind::FIRST_FACTOR_REAUTHENTICATION], $invalid],
            'an external reauthentication'      => [['kind' => ProofKind::EXTERNAL_REAUTHENTICATION], $invalid],
            'a step-up purpose'                 => [['purpose' => Purpose::STEP_UP], $invalid],
            'a reauthentication purpose'        => [['purpose' => Purpose::REAUTHENTICATE], $invalid],
            'a recovery code for an enrollment' => [['purpose' => Purpose::ENROLLMENT, 'kind' => ProofKind::RECOVERY_CODE], $invalid],
            'an evaluation not accepted'        => [['evaluation' => new Evaluation(false, true)], $invalid],
            'a time after now'                  => [['offset' => 1], $invalid],
            'a time before the session waited'  => [['offset' => -61], $invalid],
            'another identity'                  => [['identity' => 'other'], $binding],
            'an identity that is not a model'   => [['identity' => 'plain'], $binding],
            'another model with the same key'   => [['identity' => 'same key'], $binding],
            'another application'               => [['application' => 'admin'], $binding],
            'another session'                   => [['pending' => '0190e1a4-0000-7000-8000-000000000001'], $binding],
            'no session'                        => [['pending' => null], $binding],
        ];
    }

    /**
     * A further factor the pending session refuses fails `satisfy()` with the
     * reason, reported by `AuthenticationFailed`; it is not stored, and the
     * session stays pending, so a proof it takes still activates it.
     *
     * @param  array<string, mixed>  $changes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedProofs')]
    public function testSatisfyingRefusesAProofItDoesNotTake(array $changes, FailureReason $reason): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        [$pending, $credential] = self::pendingOf($this->sessions()->signIn('password', self::credentials()));

        $now = $this->now->addMinute();

        $this->clockAt($now);
        $this->recordEvents([AuthenticationFailed::class]);

        $offset     = $changes['offset']     ?? 0;
        $kind       = $changes['kind']       ?? ProofKind::ADDITIONAL_FACTOR;
        $purpose    = $changes['purpose']    ?? Purpose::SIGN_IN;
        $evaluation = $changes['evaluation'] ?? new Evaluation(true, true);
        $made       = self::madeBy($changes['identity'] ?? 'same', $identity);

        self::assertIsInt($offset);
        self::assertInstanceOf(ProofKind::class, $kind);
        self::assertInstanceOf(Purpose::class, $purpose);
        self::assertInstanceOf(Evaluation::class, $evaluation);

        $application = $changes['application'] ?? 'api';
        $bound       = array_key_exists('pending', $changes) ? $changes['pending'] : $pending->id;

        self::assertIsString($application);

        $proof  = self::adapterProof($made, $application, $bound, $purpose, $kind, $now->addSeconds($offset), $evaluation);
        $result = $this->sessions()->satisfy($credential, $proof);

        self::assertTrue($result->isFailed());
        self::assertSame($reason, $result->reason);
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
        self::assertSame(1, SessionProof::query()->count());
        self::assertTrue($this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN, at: $now))->isSignedIn());
    }

    /**
     * A proof made in the very second the session began waiting, or the second
     * it is handed over, satisfies the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofAtEitherEdgeOfItsWindowSatisfies(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        [$early, $earlyCredential] = self::pendingOf($this->sessions()->signIn('password', self::credentials()));
        [$late, $lateCredential]   = self::pendingOf($this->sessions()->signIn('password', self::credentials()));

        $this->clockAt($this->now->addMinute());

        self::assertTrue($this->sessions()->satisfy($earlyCredential, self::adapterProof($identity, 'api', $early->id, Purpose::SIGN_IN, at: $this->now))->isSignedIn());
        self::assertTrue($this->sessions()->satisfy($lateCredential, self::adapterProof($identity, 'api', $late->id, Purpose::SIGN_IN, at: $this->now->addMinute()))->isSignedIn());
    }

    /**
     * A sign-in started through an external provider that waits for a further
     * factor records its first factor and provenance with the pending session,
     * and they are the active session's, as they were, once it activates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionKeepsTheProvenance(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor();

        $result = $this->linkedResult($identity, 'connection-7', 'link-9', null, 'tenant-3', $this->now->subMinute(), $this->now->addHours(8), 'enforcement-12');

        [$pending, $credential] = self::pendingOf($this->sessions()->signInExternally($result));

        self::assertNotNull(self::provenanceOf(Session::query()->sole()));

        $this->clockAt($this->now->addMinutes(2));

        $session = $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN, at: $this->now->addMinutes(2)))->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);
        $stored = self::provenanceOf($session->record);

        self::assertCount(2, $proofs);
        self::assertSame(
            [ChannelKind::EXTERNAL_PROVIDER->value, 'connection-7', [FirstFactor::EXTERNAL_PROVIDER_METHOD]],
            [$proofs[0]->channel_kind, $proofs[0]->channel_reference, $proofs[0]->methods],
        );
        self::assertSame($this->now->subMinute()->getTimestamp(), $proofs[0]->authenticated_at->getTimestamp());
        self::assertNotNull($stored);
        self::assertSame(['connection-7', 'tenant-3', 'enforcement-12', 'link-9'], [$stored->connection_id, $stored->tenant_id, $stored->policy_version, $stored->link_id]);
        self::assertSame($this->now->addHours(8)->getTimestamp(), $stored->provider_session_expires_at?->getTimestamp());
    }

    /**
     * A session that waits for its identity to choose a principal keeps its
     * first factor, with the time it was verified, and its provenance, and the
     * session the choice activates holds them as they were.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceCarriesTheFirstFactorAndProvenanceAcross(): void
    {
        [$member, $membership] = $this->seedChooser();

        $result = $this->linkedResult($member, tenantId: 'tenant-3', authenticatedAt: $this->now->subMinute());

        [, $credential] = self::pendingOf($this->sessions(self::CHOOSERS)->signInExternally($result));

        $this->clockAt($this->now->addMinutes(2));

        $session = $this->sessions(self::CHOOSERS)->choose($credential, $membership)->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(1, $proofs);
        self::assertSame(
            [ChannelKind::EXTERNAL_PROVIDER->value, 'connection-7', 'external_provider'],
            [$proofs[0]->channel_kind, $proofs[0]->channel_reference, $proofs[0]->method],
        );
        self::assertSame($this->now->subMinute()->getTimestamp(), $proofs[0]->authenticated_at->getTimestamp());
        self::assertSame('tenant-3', self::provenanceOf($session->record)?->tenant_id);
    }

    /**
     * A choice after which the identity's factor policy asks for a further
     * factor records the principal and waits for it with the same credential,
     * so the session it activates records the time the password was verified
     * and then the further factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceThatWaitsForAFurtherFactorKeepsTheFirstFactor(): void
    {
        [$member, $membership] = $this->seedChooser();

        [, $credential] = self::pendingOf($this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test')));

        self::requireAFurtherFactor();

        $this->clockAt($this->now->addMinute());

        $pending = $this->sessions(self::CHOOSERS)->choose($credential, $membership)->pending;

        self::assertNotNull($pending);
        self::assertSame([PendingRequirement::MFA], $pending->requires);
        self::assertTrue($membership->is($pending->principal));

        $this->clockAt($this->now->addMinutes(2));

        $proof   = self::adapterProof($member, self::CHOOSERS, $pending->id, Purpose::SIGN_IN);
        $session = $this->sessions(self::CHOOSERS)->satisfy($credential, $proof)->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(2, $proofs);
        self::assertSame([ProofKind::FIRST_FACTOR->value, ChannelKind::PASSWORD->value], [$proofs[0]->kind, $proofs[0]->channel_kind]);
        self::assertSame($this->now->getTimestamp(), $proofs[0]->authenticated_at->getTimestamp());
        self::assertSame([ProofKind::ADDITIONAL_FACTOR->value, true], [$proofs[1]->kind, $proofs[1]->multifactor]);
        self::assertSame($this->now->addMinutes(2)->getTimestamp(), $proofs[1]->authenticated_at->getTimestamp());
    }

    /**
     * A proof is never recorded on a session that has no key, so none is left
     * bound to nothing.
     *
     * @return void
     */
    public function testAProofIsNeverRecordedOnASessionWithoutAKey(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A proof can only be recorded on a session that has a key.');

        self::recordProof(new Session, ProofKind::FIRST_FACTOR, $this->now);
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password', 'sso', 'external_provider']]]);
    }

    /**
     * Persist a member with two memberships, in two active tenants, so a
     * sign-in that names no principal waits for a choice.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $first  = ActivatableTenant::query()->create(['name' => 'First', 'is_active' => true]);
        $second = ActivatableTenant::query()->create(['name' => 'Second', 'is_active' => true]);

        ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $second->getKey()]);

        return [$member, ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $first->getKey()])];
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

    /**
     * The pending session a sign-in left and the credential it issued.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return array{0: \SineMacula\Laravel\Authentication\Sessions\PendingSession, 1: string}
     */
    private static function pendingOf(SignInResult $result): array
    {
        self::assertTrue($result->isPending(), 'Expected a pending session; got ' . $result->status->value);
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        return [$result->pending, $result->credential->reveal()];
    }

    /**
     * Have the additional-factor policy ask every sign-in for a further factor.
     *
     * @return void
     */
    private static function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart);
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * The identity a proof names: the one given, another persisted beside it
     * (`other`), one that is not a model (`plain`), or a model of another class
     * with the same key (`same key`).
     *
     * @param  mixed  $who
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function madeBy(mixed $who, IntegrationIdentity $identity): Identity
    {
        return match ($who) {
            'other'    => self::otherIdentity($identity),
            'plain'    => \Mockery::mock(Identity::class),
            'same key' => (new ActivatableTenantMember)->forceFill(['id' => $identity->getKey()]),
            default    => $identity,
        };
    }

    /**
     * Another identity, persisted beside the one given.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private static function otherIdentity(IntegrationIdentity $identity): IntegrationIdentity
    {
        $other           = new IntegrationIdentity;
        $other->email    = 'other.' . $identity->email;
        $other->password = $identity->password;
        $other->save();

        return $other;
    }

    /**
     * The `amr` the access token carries.
     *
     * @param  string  $token
     * @return mixed
     */
    private static function amrOf(#[\SensitiveParameter] string $token): mixed
    {
        $claims = Auth::manager()->jwt('api')->parse($token, TokenType::ACCESS);

        self::assertIsArray($claims);

        return $claims['amr'] ?? null;
    }
}
