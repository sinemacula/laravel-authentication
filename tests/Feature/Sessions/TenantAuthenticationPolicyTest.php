<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\InsufficientEvidence;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\PendingTransitions;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\External\TenantTrustingEvidencePolicy;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Feature tests of the tenant authentication policy wherever a session comes to
 * act, or keeps acting, in a tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(PendingSessions::class)]
#[CoversClass(SessionActivation::class)]
#[CoversClass(PendingTransitions::class)]
#[CoversClass(SessionRefresh::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(RefreshRotationStore::class)]
#[CoversClass(TenantPolicyChanges::class)]
#[CoversClass(AbstractGuard::class)]
final class TenantAuthenticationPolicyTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, whose sign-ins wait for a choice of principal. */
    private const string CHOOSERS = 'choosers';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy The policy tenants answer with. */
    private ScriptedTenantAuthenticationPolicy $policy;

    /** @var \Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck The check judging further factors. */
    private ProofJudgingRequirementCheck $check;

    /**
     * Freeze the clocks, create the tables, bind the scripted policy and check,
     * and add a route behind the `auth` middleware of the members' guard.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        $this->policy = new ScriptedTenantAuthenticationPolicy;
        $this->check  = new ProofJudgingRequirementCheck;

        app()->instance(TenantAuthenticationPolicy::class, $this->policy);
        app()->instance(RequirementCheck::class, $this->check);

        Route::middleware('auth:members')->get('/me', static fn (): array => ['ok' => true]);
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
     * A tenant requiring a further factor holds the sign-in pending until the
     * bound check finds it met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantRequiringAFactorHoldsTheSignInUntilTheCheckIsMet(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->policy->requirement = new TenantRequirement('v1', new Requirement(new RequirementPart));

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertSame([PendingRequirement::MFA], $result->pending->requires);
        self::assertIsModel($membership, $result->pending->principal);

        $row = Session::query()->sole();

        self::assertSame('v1', $row->getTenantPolicyVersion());
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $row->getTenantId());

        app()->instance(RequirementCheck::class, new MeetNoRequirement);

        $waiting = $this->sessions('members')->satisfy(
            $result->credential->reveal(),
            self::adapterProof($member, 'members', $result->pending->id, Purpose::SIGN_IN),
            self::requestClient(),
        );

        self::assertTrue($waiting->isPending());
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());

        app()->instance(RequirementCheck::class, $this->check);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $active = $this->sessions('members')->satisfy(
            $result->credential->reveal(),
            self::adapterProof($member, 'members', $result->pending->id, Purpose::SIGN_IN),
            self::requestClient(),
        );

        self::assertTrue($active->isSignedIn());
        self::assertSame('v2', Session::query()->sole()->getTenantPolicyVersion());
        self::assertNotSame([], $this->check->judged);
    }

    /**
     * A tenant requiring a connection refuses any other sign-in as
     * `sso_required`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantRequiringAConnectionRefusesAnyOtherSignIn(): void
    {
        [$member, $membership] = $this->seedMember();

        $this->policy->requirement = new TenantRequirement('v1', connections: ['conn-a']);

        $this->recordEvents([AuthenticationFailed::class]);

        $refused = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame(FailureReason::SSO_REQUIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(0, Session::query()->count());

        $signedIn = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a'), self::asPrincipal($membership));

        self::assertTrue($signedIn->isSignedIn());
        self::assertSame('v1', Session::query()->sole()->getTenantPolicyVersion());
    }

    /**
     * A choice of principal answers to the chosen tenant's policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceAnswersToTheChosenTenantsPolicy(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $this->policy->answer = static fn (TenantPolicyContext $context): TenantRequirement => $context->tenant->getTenantIdentifier() === $first->tenant_id
            ? new TenantRequirement('sso', connections: ['conn-a'])
            : new TenantRequirement('mfa', new Requirement(new RequirementPart));

        $result = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'), self::requestContext());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);

        $refused = $this->sessions(self::CHOOSERS)->choose($result->credential->reveal(), $first, self::requestClient());

        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame([PendingRequirement::PRINCIPAL], Session::query()->sole()->getRequires());
        self::assertNull(Session::query()->sole()->principal_id);

        $waiting = $this->sessions(self::CHOOSERS)->choose($result->credential->reveal(), $second, self::requestClient());

        self::assertTrue($waiting->isPending());
        self::assertSame([PendingRequirement::MFA], $waiting->pending?->requires);

        $row = Session::query()->sole();

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($second->tenant_id), $row->getTenantId());

        $active = $this->sessions(self::CHOOSERS)->satisfy(
            $result->credential->reveal(),
            self::adapterProof($member, self::CHOOSERS, $row->getKey(), Purpose::SIGN_IN),
            self::requestClient(),
        );

        self::assertTrue($active->isSignedIn());
        self::assertSame('mfa', Session::query()->sole()->getTenantPolicyVersion());
    }

    /**
     * A choice of principal is judged on the evidence the pending session holds
     * accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsJudgedOnThePendingSessionsAcceptedEvidence(): void
    {
        [$member, , $second] = $this->seedChooser();

        $this->policy->requirement = new TenantRequirement('mfa', new Requirement(multifactor: new RequirementPart));

        $evidence = new ExternalEvidence(['mfa'], null, $this->now);
        $policy   = new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]);

        app()->instance(ExternalEvidencePolicy::class, $policy);

        $trusted = $this->sessions(self::CHOOSERS)->signInExternally($this->linkedResult($member, evidence: $evidence), self::requestContext());

        self::assertTrue($trusted->isPending());
        self::assertSame([PendingRequirement::PRINCIPAL], $trusted->pending?->requires);

        $active = $this->sessions(self::CHOOSERS)->choose((string) $trusted->credential?->reveal(), $second, self::requestClient());

        self::assertTrue($active->isSignedIn());
        self::assertSame($second->tenant_id, $policy->asked[1]['subject']->tenant?->getTenantIdentifier());
        self::assertSame([], $this->check->judged);

        app()->instance(ExternalEvidencePolicy::class, new InsufficientEvidence);

        $untrusted = $this->sessions(self::CHOOSERS)->signInExternally($this->linkedResult($member, evidence: $evidence), self::requestContext());
        $waiting   = $this->sessions(self::CHOOSERS)->choose((string) $untrusted->credential?->reveal(), $second, self::requestClient());

        self::assertTrue($waiting->isPending());
        self::assertSame([PendingRequirement::MFA], $waiting->pending?->requires);
    }

    /**
     * A refresh and a switch are judged on the evidence the session holds
     * accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshAndASwitchAreJudgedOnTheSessionsAcceptedEvidence(): void
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $evidence = new ExternalEvidence(['mfa'], null, $this->now);
        $session  = $this->sessions('members')->signInExternally($this->linkedResult($member, evidence: $evidence), self::asPrincipal($first))->session;

        self::assertNotNull($session);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart));

        $refreshed = $this->sessions('members')->refresh(self::bodyToken($session->tokens), self::requestClient());

        self::assertTrue($refreshed->isRefreshed());
        self::assertSame('v2', Session::query()->sole()->getTenantPolicyVersion());

        $switched = $this->sessions('members')->switchTo(
            PresentedRefreshToken::fromBody($refreshed->session?->tokens->refreshToken?->reveal() ?? ''),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertTrue($switched->isSwitched());
        self::assertSame([], $this->check->judged);

        app()->instance(ExternalEvidencePolicy::class, new InsufficientEvidence);

        $this->policy->requirement = new TenantRequirement('v3', new Requirement(multifactor: new RequirementPart));

        $returned = $this->sessions('members')->refresh(self::bodyToken($switched->session?->tokens), self::requestClient());

        self::assertTrue($returned->isPending());
        self::assertSame([PendingRequirement::MFA], $returned->pending?->requires);
    }

    /**
     * The policy is asked with the client of the call that asks, and with none
     * by the policy-change helper and a pending session's lookup.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePolicyIsAskedWithTheClientOfTheCallThatAsks(): void
    {
        [$member] = $this->seedMember();

        $this->policy->requirement = new TenantRequirement('v1', new Requirement(new RequirementPart));

        $sessions = $this->sessions('members');
        $pending  = $sessions->signIn('password', self::credentials('member@example.test'), new SignInContext(new ClientContext('203.0.113.1', 'agent')));

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);
        self::assertNotNull($sessions->pending($pending->credential->reveal()));

        $active = $sessions->satisfy(
            $pending->credential->reveal(),
            self::adapterProof($member, 'members', $pending->pending->id, Purpose::SIGN_IN),
            new ClientContext('203.0.113.2', 'agent'),
        );

        self::assertTrue($active->isSignedIn());

        $refreshed = $sessions->refresh(self::bodyToken($active->session?->tokens), new ClientContext('203.0.113.3', 'agent'));

        self::assertTrue($refreshed->isRefreshed());

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $switched = $sessions->switchTo(
            PresentedRefreshToken::fromBody($refreshed->session?->tokens->refreshToken?->reveal() ?? ''),
            SwitchTarget::principal($second),
            new ClientContext('203.0.113.4', 'agent'),
        );

        self::assertTrue($switched->isSwitched());

        $sessions->tenantPolicyChanged($other);

        self::assertSame(
            ['203.0.113.1', null, '203.0.113.2', '203.0.113.3', '203.0.113.4', null],
            array_map(static fn (TenantPolicyContext $context): ?string => $context->client?->ip, $this->policy->asked),
        );
    }

    /**
     * One tenant's connection never meets another tenant's further factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneTenantsConnectionNeverMeetsAnotherTenantsFactor(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $policy = new TenantTrustingEvidencePolicy([(string) IdentifierCoercion::stringify($tenant->getKey()) => ['conn-a']]);

        app()->instance(ExternalEvidencePolicy::class, $policy);

        $this->policy->requirement = new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart));

        $evidence = new ExternalEvidence(['mfa'], null, $this->now);
        $trusted  = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a', evidence: $evidence), self::asPrincipal($first));
        $foreign  = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a', evidence: $evidence), self::asPrincipal($second));

        self::assertTrue($trusted->isSignedIn());
        self::assertTrue($foreign->isPending());
        self::assertSame([PendingRequirement::MFA], $foreign->pending?->requires);
        self::assertSame(
            [null, $tenant->getKey(), null, $other->getKey()],
            array_map(static fn (EvidenceSubject $subject): mixed => $subject->tenant?->getTenantIdentifier(), $policy->subjects),
        );
        self::assertSame(['conn-a'], array_values(array_unique(array_column($policy->subjects, 'connectionId'))));
    }

    /**
     * Evidence only one tenant trusts is accepted and meets only that tenant's
     * requirement.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceOnlyOneTenantTrustsIsAcceptedAndMeetsOnlyThatTenant(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $tenantId = (string) IdentifierCoercion::stringify($tenant->getKey());
        $evidence = new ExternalEvidence(['mfa'], null, $this->now);

        app()->instance(ExternalEvidencePolicy::class, new TenantTrustingEvidencePolicy([$tenantId => ['conn-a']]));

        $this->policy->requirement = new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart));

        $trusted = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a', evidence: $evidence), self::asPrincipal($first));

        $record = $trusted->session?->record;

        self::assertNotNull($record);
        self::assertEquals($evidence, SessionProofs::provenance($record)?->evidence);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $identityLevel = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a', evidence: $evidence), self::asPrincipal($first));

        self::assertTrue($identityLevel->isPending());

        app()->instance(ExternalEvidencePolicy::class, new TenantTrustingEvidencePolicy(['' => ['conn-a'], $tenantId => ['conn-a']]));

        self::assertTrue($this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a', evidence: $evidence), self::asPrincipal($first))->isSignedIn());
    }

    /**
     * A refresh that falls short of a newly required factor returns the session
     * to pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshThatFallsShortOfAFactorReturnsTheSessionToPending(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signedIn();

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $this->recordEvents([SessionReturnedToPending::class, SessionActivated::class, AuthenticationFailed::class]);

        $returned = $this->sessions('members')->refresh(self::bodyToken($session->tokens), self::requestClient());

        self::assertTrue($returned->isPending());
        self::assertNull($returned->session);
        self::assertNotNull($returned->pending);
        self::assertNotNull($returned->credential);
        self::assertSame([PendingRequirement::MFA], $returned->pending->requires);
        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION], $returned->pending->requirement->kinds());

        $event = $this->recordedEvent(SessionReturnedToPending::class);

        self::assertSame(AuthenticationFlow::REFRESH, $event->flow);
        self::assertSame(['mfa'], $event->requires);
        self::assertNull($event->previousPrincipalId);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me')->assertUnauthorized();

        self::assertSame(
            FailureReason::SESSION_PENDING,
            $this->sessions('members')->refresh(self::bodyToken($session->tokens), self::requestClient())->reason,
        );
        self::assertNull(Session::query()->sole()->getRevokedAt());

        $this->clockAt($this->now->addSeconds(5));

        $active = $this->sessions('members')->satisfy(
            $returned->credential->reveal(),
            self::adapterProof($member, 'members', $returned->pending->id, Purpose::SIGN_IN),
            self::requestClient(),
        );

        self::assertTrue($active->isSignedIn());
        self::assertNotNull($active->session);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), IdentifierCoercion::stringify($active->session->record->getKey()));
        self::assertNotNull($this->recordedEvent(SessionActivated::class));

        $row = Session::query()->sole();

        self::assertSame('v2', $row->getTenantPolicyVersion());
        self::assertSame($this->now->getTimestamp(), $row->getSwitchedAt()?->getTimestamp());

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me')->assertUnauthorized();

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $active->session->tokens->accessToken->reveal()])->getJson('/me')->assertOk();
    }

    /**
     * A refresh returning to pending names the strictest of the tenant's and
     * the identity's requirements.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshReturningToPendingNamesTheIdentitysRequirementToo(): void
    {
        $this->seedMember();

        $session = $this->signedIn();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart));

        $returned = $this->sessions('members')->refresh(self::bodyToken($session->tokens), self::requestClient());

        self::assertNotNull($returned->pending);
        self::assertNotNull($returned->credential);
        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::MULTIFACTOR], $returned->pending->requirement->kinds());
        self::assertEquals($returned->pending->requirement, $this->sessions('members')->pending($returned->credential)?->requirement);
    }

    /**
     * A return to pending forgets only the guard's binding to that session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnToPendingForgetsOnlyTheGuardsBindingToThatSession(): void
    {
        $this->seedMember();

        $other   = $this->signedIn();
        $guard   = $this->freshGuard('members');
        $service = self::sessionsOf($guard);
        $kept    = $service->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($kept);
        self::assertSame($kept->record, $guard->session());

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        self::assertTrue($service->refresh(self::bodyToken($other->tokens), self::requestClient())->isPending());
        self::assertSame($kept->record, $guard->session());

        self::assertTrue($service->refresh(self::bodyToken($kept->tokens), self::requestClient())->isPending());
        self::assertFalse($guard->hasUser());
        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->session());
        self::assertNull($guard->tenant());
    }

    /**
     * A refresh that needs another connection is refused as `sso_required` and
     * revokes the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshThatNeedsAnotherConnectionRevokesTheSession(): void
    {
        $this->seedMember();

        $session = $this->signedIn();

        $this->policy->requirement = new TenantRequirement('v2', connections: ['conn-a']);

        $this->recordEvents([SessionRevoked::class]);

        $refused = $this->sessions('members')->refresh(self::bodyToken($session->tokens), self::requestClient());

        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, Session::query()->sole()->getRevokedReason());
    }

    /**
     * A plain refresh meets the tenant's policy and reports with the client
     * given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainRefreshMeetsThePolicyAndReportsWithTheClientGiven(): void
    {
        $this->seedMember();

        $returning = $this->signedIn();
        $revoking  = $this->signedIn();
        $client    = self::crossSiteClient();

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $this->recordEvents([SessionReturnedToPending::class, SessionRevoked::class]);

        $returned = $this->sessions('members')->refresh(self::presentedToken((string) $returning->tokens->refreshToken?->reveal(), RefreshTokenSource::BODY), $client);

        self::assertTrue($returned->isPending());
        self::assertNotNull($returned->credential);
        self::assertSame(RefreshTokenSource::BODY, $returned->source);
        self::assertSame($client, $this->recordedEvent(SessionReturnedToPending::class)->context->client);

        $this->policy->requirement = new TenantRequirement('v3', connections: ['conn-a']);

        $refused = $this->sessions('members')->refresh(self::presentedToken((string) $revoking->tokens->refreshToken?->reveal(), RefreshTokenSource::BODY), $client);

        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame($client, $this->recordedEvent(SessionRevoked::class)->context->client);
    }

    /**
     * A refresh that meets the policy records the version answered when it
     * changed, in the rotation's compare-and-swap.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshThatMeetsThePolicyRecordsItsVersion(): void
    {
        $this->seedMember();

        $session = $this->signedIn();

        self::assertNull(Session::query()->sole()->getTenantPolicyVersion());

        $this->policy->requirement = new TenantRequirement('v3');

        self::assertTrue($this->sessions('members')->refresh(self::bodyToken($session->tokens), self::requestClient())->isRefreshed());
        self::assertSame('v3', Session::query()->sole()->getTenantPolicyVersion());
    }

    /**
     * `attempt()` refuses a principal whose tenant requires a further factor or
     * a connection.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRefusesWhatTheTenantRequires(): void
    {
        $this->seedMember();

        $this->recordEvents([AuthenticationFailed::class]);

        $this->policy->requirement = new TenantRequirement(factor: new Requirement(new RequirementPart));

        self::assertFalse(Auth::guard('members')->attempt(self::credentials('member@example.test')));
        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertCount(1, $this->check->judged);

        $password = $this->check->judged[0]->firstFactor;

        self::assertSame(ProofKind::FIRST_FACTOR, $password->kind);
        self::assertSame('password', $password->method);
        self::assertSame(ChannelKind::PASSWORD, $password->channel->kind);
        self::assertSame(['pwd'], $password->methods);
        self::assertTrue($password->authenticatedAt->equalTo($this->now));
        self::assertNull($this->check->judged[0]->session);

        $this->policy->requirement = new TenantRequirement(connections: ['conn-a']);

        Auth::forgetGuards();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertFalse(Auth::guard('members')->attempt(self::credentials('member@example.test')));
        self::assertSame(FailureReason::SSO_REQUIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);

        $this->policy->requirement = new TenantRequirement;

        Auth::forgetGuards();

        self::assertTrue(Auth::guard('members')->attempt(self::credentials('member@example.test')));
    }

    /**
     * A policy change revokes the tenant's active sessions that no longer meet
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyChangeEndsTheSessionsThatNoLongerMeetIt(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->seedMember('other@example.test');

        $short   = $this->signedIn();
        $met     = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a'), self::asPrincipal($membership))->session?->record;
        $current = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-b'), self::asPrincipal($membership))->session?->record;
        $outside = $this->signedIn('other@example.test');

        self::assertNotNull($met);
        self::assertNotNull($current);

        DB::table('authentication_sessions')->where('id', $current->getKey())->update(['tenant_policy_version' => 'v9']);

        $pending = $this->pendingFor();

        $this->policy->answer = static fn (TenantPolicyContext $context): TenantRequirement => new TenantRequirement(
            $context->session?->getSessionIdentifier() === $current->getKey() ? 'v9' : 'v8',
            connections: ['conn-a'],
        );

        $this->recordEvents([SessionRevoked::class]);

        $revoked = $this->sessions('members')->tenantPolicyChanged($tenant);

        self::assertSame(2, $revoked);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($short->record->getKey())->getRevokedReason());
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($pending)->getRevokedReason());
        self::assertNull($this->rowOf($met->getKey())->getRevokedAt());
        self::assertSame('v8', $this->rowOf($met->getKey())->getTenantPolicyVersion());
        self::assertNull($this->rowOf($current->getKey())->getRevokedAt());
        self::assertNull($this->rowOf($outside->record->getKey())->getRevokedAt());
        self::assertCount(2, $this->recordedClasses());
    }

    /**
     * A policy change leaves a pending session that lacks only a further
     * factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyChangeLeavesAPendingSessionThatLacksOnlyAFactor(): void
    {
        [, , $tenant] = $this->seedMember();

        $active  = $this->signedIn();
        $pending = $this->pendingFor();

        $this->policy->requirement = new TenantRequirement('v1', new Requirement(new RequirementPart));

        app()->instance(RequirementCheck::class, new MeetNoRequirement);

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertNotNull($this->rowOf($active->record->getKey())->getRevokedAt());
        self::assertNull($this->rowOf($pending)->getRevokedAt());
    }

    /**
     * A policy change judges an external session on the evidence the changed
     * tenant trusts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyChangeJudgesExternalSessionsOnTheTenantsTrustedEvidence(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $other    = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $evidence = new ExternalEvidence(['mfa'], null, $this->now);

        app()->instance(ExternalEvidencePolicy::class, new TenantTrustingEvidencePolicy([
            (string) IdentifierCoercion::stringify($tenant->getKey()) => ['conn-a'],
            (string) IdentifierCoercion::stringify($other->getKey())  => ['conn-b'],
        ]));

        $trusted = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-a', evidence: $evidence), self::asPrincipal($membership))->session?->record;
        $foreign = $this->sessions('members')->signInExternally($this->linkedResult($member, 'conn-b', evidence: $evidence), self::asPrincipal($membership))->session?->record;

        self::assertNotNull($trusted);
        self::assertNotNull($foreign);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart));

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertNull($this->rowOf($trusted->getKey())->getRevokedAt());
        self::assertSame('v2', $this->rowOf($trusted->getKey())->getTenantPolicyVersion());
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, $this->rowOf($foreign->getKey())->getRevokedReason());
        self::assertCount(1, $this->check->judged);
    }

    /**
     * A policy change rolls back with the caller's transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPolicyChangeRollsBackWithTheCallersTransaction(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $this->policy->requirement = new TenantRequirement(connections: ['conn-a']);

        $this->recordEvents([SessionRevoked::class]);

        DB::beginTransaction();

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));

        DB::rollBack();

        self::assertNull($this->rowOf($session->record->getKey())->getRevokedAt());
        self::assertSame([], $this->recordedClasses());

        self::assertSame(1, $this->sessions('members')->tenantPolicyChanged($tenant));
        self::assertSame(0, $this->sessions('members')->tenantPolicyChanged($tenant));
    }

    /**
     * Register the session guards and the choosers' guard.
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
     * Sign the seeded member in with its password.
     *
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $email = 'member@example.test'): SignedInSession
    {
        $result = $this->sessions('members')->signIn('password', self::credentials($email), self::requestContext());

        self::assertNotNull($result->session, 'Expected the sign-in to start a session; it failed with ' . $result->reason?->value);

        return $result->session;
    }

    /**
     * The stored row of the session with the key given.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function rowOf(mixed $key): Session
    {
        return Session::query()->whereKey($key)->firstOrFail();
    }

    /**
     * A pending session of the member waiting on a further factor its tenant
     * asked for, and its key.
     *
     * @param  string  $email
     * @return mixed
     *
     * @throws \Throwable
     */
    private function pendingFor(string $email = 'member@example.test'): mixed
    {
        $requirement = $this->policy->requirement;
        $answer      = $this->policy->answer;

        $this->policy->answer      = null;
        $this->policy->requirement = new TenantRequirement(factor: new Requirement(new RequirementPart));

        $result = $this->sessions('members')->signIn('password', self::credentials($email), self::requestContext());

        self::assertTrue($result->isPending());

        $this->policy->requirement = $requirement;
        $this->policy->answer      = $answer;

        return $result->pending?->id;
    }

    /**
     * A chooser with two memberships, each in a tenant of its own.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership, 2: \Tests\Integration\Fixtures\ChoosingMembership}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedChooser(): array
    {
        $member      = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return [$member, ...$memberships];
    }

    /**
     * Freeze every clock the package reads at the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        $this->now = $at;

        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }
}
