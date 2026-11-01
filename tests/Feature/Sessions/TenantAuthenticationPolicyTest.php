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
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
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
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Feature tests of the tenant authentication policy wherever a session comes to
 * act, or keeps acting, in a tenant: a sign-in, a choice of principal, the
 * further factor that activates a pending session, a refresh, `attempt()`, and
 * the policy-change helper, with a scripted policy and check, through the
 * session service and the guards against a real database.
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
final class TenantAuthenticationPolicyTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

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
     * A tenant that requires a further factor holds the sign-in pending on
     * `mfa`, its principal and tenant recorded with the policy's version; the
     * factor activates it only once the bound check finds it met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantRequiringAFactorHoldsTheSignInUntilTheCheckIsMet(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->policy->requirement = new TenantRequirement('v1', new Requirement(new RequirementPart));

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'));

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertSame([PendingRequirement::MFA], $result->pending->requires);
        self::assertTrue($membership->is($result->pending->principal));

        $row = Session::query()->sole();

        self::assertSame('v1', $row->getTenantPolicyVersion());
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $row->getTenantId());

        app()->instance(RequirementCheck::class, new MeetNoRequirement);

        $waiting = $this->sessions('members')->satisfy($result->credential, self::adapterProof($member, 'members', $result->pending->id, Purpose::SIGN_IN));

        self::assertTrue($waiting->isPending());
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());

        app()->instance(RequirementCheck::class, $this->check);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $active = $this->sessions('members')->satisfy($result->credential, self::adapterProof($member, 'members', $result->pending->id, Purpose::SIGN_IN));

        self::assertTrue($active->isSignedIn());
        self::assertSame('v2', Session::query()->sole()->getTenantPolicyVersion());
        self::assertNotSame([], $this->check->judged);
    }

    /**
     * A tenant that requires a connection refuses a password sign-in as
     * `sso_required`, writing nothing; a session established through a named
     * connection signs in.
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

        $refused = $this->sessions('members')->signIn('password', self::credentials('member@example.test'));

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame(FailureReason::SSO_REQUIRED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(0, Session::query()->count());

        $signedIn = $this->sessions('members')->start($member, $membership, 'sso', null, new Provenance('conn-a'));

        self::assertTrue($signedIn->isSignedIn());
        self::assertSame('v1', Session::query()->sole()->getTenantPolicyVersion());
    }

    /**
     * A choice of a principal whose tenant requires a connection is refused for
     * that principal alone, the session left pending; one whose tenant requires
     * a further factor records the principal and waits on `mfa`.
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

        $result = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'));

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);

        $refused = $this->sessions(self::CHOOSERS)->choose($result->credential, $first);

        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame([PendingRequirement::PRINCIPAL], Session::query()->sole()->getRequires());
        self::assertNull(Session::query()->sole()->principal_id);

        $waiting = $this->sessions(self::CHOOSERS)->choose($result->credential, $second);

        self::assertTrue($waiting->isPending());
        self::assertSame([PendingRequirement::MFA], $waiting->pending?->requires);

        $row = Session::query()->sole();

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($second->tenant_id), $row->getTenantId());

        $active = $this->sessions(self::CHOOSERS)->satisfy($result->credential, self::adapterProof($member, self::CHOOSERS, $row->getKey(), Purpose::SIGN_IN));

        self::assertTrue($active->isSignedIn());
        self::assertSame('mfa', Session::query()->sole()->getTenantPolicyVersion());
    }

    /**
     * A tenant that comes to require a further factor returns the session to
     * pending at its next refresh: no pair, the pending credential, the old
     * access token refused at once and the old refresh token refused as pending
     * without revoking; the factor activates it again (`SessionActivated`), its
     * floor moved past every earlier token.
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

        $returned = $this->sessions('members')->refresh($session->tokens->refreshToken);

        self::assertTrue($returned->isPending());
        self::assertNull($returned->session);
        self::assertNotNull($returned->pending);
        self::assertNotNull($returned->credential);
        self::assertSame([PendingRequirement::MFA], $returned->pending->requires);

        $event = $this->recordedEvent(SessionReturnedToPending::class);

        self::assertSame(AuthenticationFlow::REFRESH, $event->flow);
        self::assertSame(['mfa'], $event->requires);
        self::assertNull($event->previousPrincipalId);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken])->getJson('/me')->assertUnauthorized();

        self::assertSame(FailureReason::SESSION_PENDING, $this->sessions('members')->refresh($session->tokens->refreshToken)->reason);
        self::assertNull(Session::query()->sole()->getRevokedAt());

        $this->clockAt($this->now->addSeconds(5));

        $active = $this->sessions('members')->satisfy($returned->credential, self::adapterProof($member, 'members', $returned->pending->id, Purpose::SIGN_IN));

        self::assertTrue($active->isSignedIn());
        self::assertNotNull($active->session);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), IdentifierCoercion::stringify($active->session->record->getKey()));
        self::assertNotNull($this->recordedEvent(SessionActivated::class));

        $row = Session::query()->sole();

        self::assertSame('v2', $row->getTenantPolicyVersion());
        self::assertSame($this->now->getTimestamp(), $row->getSwitchedAt()?->getTimestamp());

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken])->getJson('/me')->assertUnauthorized();

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $active->session->tokens->accessToken])->getJson('/me')->assertOk();
    }

    /**
     * A tenant that comes to require a connection the session was not
     * established through refuses its next refresh as `sso_required` and
     * revokes it (`tenant_policy_changed`), so it never refreshes again.
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

        $refused = $this->sessions('members')->refresh($session->tokens->refreshToken);

        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, Session::query()->sole()->getRevokedReason());
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

        self::assertTrue($this->sessions('members')->refresh($session->tokens->refreshToken)->isRefreshed());
        self::assertSame('v3', Session::query()->sole()->getTenantPolicyVersion());
    }

    /**
     * `attempt()`, which cannot wait, refuses a principal whose tenant requires
     * a further factor as `additional_factor_required`, and one whose tenant
     * requires a connection as `sso_required`.
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
     * it, records the version on those that do, skips those already at it,
     * leaves a pending session that lacks only a factor, and touches no other
     * tenant's session.
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
        $met     = $this->sessions('members')->start($member, $membership, 'sso', null, new Provenance('conn-a'))->session?->record;
        $current = $this->sessions('members')->start($member, $membership, 'sso', null, new Provenance('conn-b'))->session?->record;
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
     * A pending session that lacks only a further factor is left for its
     * activation to judge; an active one is revoked.
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
     * Inside a caller's transaction that rolls back, nothing is revoked and no
     * revocation is reported; called again outside it, the session is revoked,
     * and a third call finds nothing left to revoke.
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
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password', 'sso']]]);
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
        $result = $this->sessions('members')->signIn('password', self::credentials($email));

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
     * A pending session of the member signing in with the email given, in its
     * tenant, waiting on a further factor its tenant asked for at sign-in, and
     * its key.
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

        $result = $this->sessions('members')->signIn('password', self::credentials($email));

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
