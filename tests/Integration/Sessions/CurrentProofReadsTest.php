<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementJudge;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Every requirement judgement the package makes under a session's row lock, on
 * PostgreSQL and MySQL, on two connections to one database, inside a caller's
 * transaction at READ COMMITTED and at REPEATABLE READ that made a plain read
 * first: meanwhile the other connection commits a change to the session's
 * proofs as the package writes it (a step-up, a proof voided, a
 * reauthentication bringing accepted evidence, or the session's key reused by
 * another sign-in), each of which writes the session's row; then the caller's
 * transaction runs the judgement.
 *
 * At READ COMMITTED, and on MySQL at REPEATABLE READ (whose plain reads return
 * the snapshot of the transaction's first read, so only the shared lock the
 * judgement's reads take there see the change), the judgement is made on the
 * change committed: a step-up counts, a voided proof never does, and a reused
 * key's session is judged on its own proofs and provenance. On PostgreSQL's
 * REPEATABLE READ no read can see past the snapshot, so the session's lock or
 * issuance guard fails to serialise instead, and once the caller retries the
 * whole transaction the judgement is made on the change. A judgement that read
 * the snapshot would return a session to pending for want of the step-up, keep
 * it active on the voided proof, or keep a session the reused key no longer
 * establishes through the tenant's connection.
 *
 * Skipped on SQLite, whose in-memory database each connection would have to
 * itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofs::class)]
#[CoversClass(RequirementJudge::class)]
#[CoversClass(TenantPolicyCheck::class)]
#[CoversClass(FactorRevocations::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(SessionSwitch::class)]
#[CoversClass(PendingSessions::class)]
#[CoversClass(ExternalReauthentication::class)]
#[CoversClass(TenantPolicyChanges::class)]
final class CurrentProofReadsTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var string The second connection to the test database, the one that commits the change. */
    private const string OTHER = 'other';

    /** @var string Guard over `ChoosingMember`, whose sign-ins wait for a choice of principal. */
    private const string CHOOSERS = 'choosers';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy The policy tenants answer with. */
    private ScriptedTenantAuthenticationPolicy $policy;

    /**
     * Skip where two connections cannot share the database, add the second
     * connection, freeze the clocks, create the tables, and bind the scripted
     * tenant policy and the check that judges further factors.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('Two connections need a shared database server.');
        }

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::OTHER, $config->get('database.connections.' . $config->string('database.default')));

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();

        $this->policy = new ScriptedTenantAuthenticationPolicy;

        app()->instance(TenantAuthenticationPolicy::class, $this->policy);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        self::limitLockWaits('testing');
        self::limitLockWaits(self::OTHER);
    }

    /**
     * Close the second connection, drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::disconnect(self::OTHER);

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A factor change counts a step-up committed after the caller's first read:
     * a session whose identity now asks for a further factor, which the step-up
     * meets, stays active.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAFactorChangeCountsAStepUpCommittedMeanwhile(string $level): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn('api', $identity);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $changed = $this->judgeAfter(
            $level,
            fn () => $this->stepUpElsewhere($identity, $session, 'factor-1'),
            fn (): bool => $this->sessions()->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $session->record)->isActive(),
        );

        self::assertTrue($changed);
        self::assertSame('active', DB::table('authentication_sessions')->value('status'));
    }

    /**
     * A factor's removal never counts a proof another factor's removal voided
     * after the caller's first read: with both factors' proofs voided, the
     * session owes its further factor again and returns to pending.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAFactorRemovalNeverCountsAProofVoidedMeanwhile(string $level): void
    {
        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $session = $this->satisfied('api', $identity, 'factor-1');

        self::assertTrue($this->sessions()->stepUp($this->proof($identity, 'api', $session->record->getKey(), 'factor-2', Purpose::STEP_UP))->isIssued());

        $removed = $this->judgeAfter(
            $level,
            fn () => $this->voidElsewhere('api', $session->record->getKey(), 'factor-2'),
            fn (): bool => $this->sessions()->factorRemoved($identity, 'factor-1', $session->record)->isPending(),
        );

        self::assertTrue($removed);
        self::assertSame('pending', DB::table('authentication_sessions')->value('status'));
    }

    /**
     * A refresh counts a step-up committed after the caller's first read: a
     * session whose tenant now asks for a further factor, which the step-up
     * meets, is handed a pair.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefreshCountsAStepUpCommittedMeanwhile(string $level): void
    {
        [$member, , $tenant] = $this->seedMember();

        $session = $this->signedIn('members', $member);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $refreshed = $this->judgeAfter(
            $level,
            fn () => $this->stepUpElsewhere($member, $session, 'factor-1'),
            fn (): bool => $this->sessions('members')->refresh((string) $session->tokens->refreshToken?->reveal())->isRefreshed(),
        );

        self::assertTrue($refreshed);
        self::assertSame('v2', DB::table('authentication_sessions')->where('tenant_id', IdentifierCoercion::stringify($tenant->getKey()))->value('tenant_policy_version'));
    }

    /**
     * A switch counts a step-up committed after the caller's first read: a
     * switch to a principal whose tenant asks for a further factor, which the
     * step-up meets, switches.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASwitchCountsAStepUpCommittedMeanwhile(string $level): void
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $target = IdentifierCoercion::stringify($other->getKey());

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), new SignInContext(new ClientContext(null, null), principal: $first));

        self::assertNotNull($result->session);

        $session = $result->session;

        $this->policy->answer = static fn (TenantPolicyContext $context): TenantRequirement => IdentifierCoercion::stringify($context->tenant->getTenantIdentifier()) === $target
            ? new TenantRequirement('v1', new Requirement(new RequirementPart))
            : new TenantRequirement;

        $switched = $this->judgeAfter(
            $level,
            fn () => $this->stepUpElsewhere($member, $session, 'factor-1'),
            fn (): bool => $this->sessions('members')->switchTo((string) $session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->isSwitched(),
        );

        self::assertTrue($switched);
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
    }

    /**
     * A choice never counts a further factor's proof voided after the caller's
     * first read: the pending session that had satisfied its further factor
     * waits on it again, the choice recorded, instead of activating.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAChoiceNeverCountsAProofVoidedMeanwhile(string $level): void
    {
        [$member, $first] = $this->seedChooser();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $pending = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'));

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $credential = $pending->credential->reveal();
        $satisfied  = $this->sessions(self::CHOOSERS)->satisfy($credential, $this->proof($member, self::CHOOSERS, $pending->pending->id, 'factor-1', Purpose::SIGN_IN));

        self::assertSame([PendingRequirement::PRINCIPAL], $satisfied->pending?->requires);

        $chosen = $this->judgeAfter(
            $level,
            fn () => $this->voidElsewhere(self::CHOOSERS, $pending->pending->id, 'factor-1'),
            fn (): ?array => $this->sessions(self::CHOOSERS)->choose($credential, $first)->pending?->requires,
        );

        self::assertSame([PendingRequirement::MFA], $chosen);
        self::assertSame('pending', DB::table('authentication_sessions')->value('status'));
    }

    /**
     * A further factor satisfied never counts with a proof voided after the
     * caller's first read: a session whose requirement takes two further
     * factors, one voided meanwhile, keeps waiting with the other alone.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASatisfactionNeverCountsAProofVoidedMeanwhile(string $level): void
    {
        $identity = $this->seedIdentity();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, self::twoFactorCheck());

        $pending = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $credential = $pending->credential->reveal();
        $key        = $pending->pending->id;

        self::assertTrue($this->sessions()->satisfy($credential, $this->proof($identity, 'api', $key, 'factor-1', Purpose::SIGN_IN))->isPending());

        $satisfied = $this->judgeAfter(
            $level,
            fn () => $this->voidElsewhere('api', $key, 'factor-1'),
            fn (): bool => $this->sessions()->satisfy($credential, $this->proof($identity, 'api', $key, 'factor-2', Purpose::SIGN_IN))->isPending(),
        );

        self::assertTrue($satisfied);
        self::assertSame('pending', DB::table('authentication_sessions')->value('status'));
    }

    /**
     * A refresh of a session an external provider established counts evidence a
     * reauthentication committed after the caller's first read: evidence the
     * evidence policy says meets the tenant's multifactor requirement hands the
     * session a pair.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARefreshCountsEvidenceAcceptedMeanwhile(string $level): void
    {
        [$member, $membership] = $this->seedMember();

        $session = $this->sessions('members')->signInExternally($this->linkedResult($member, subject: 'subject-1'), self::asPrincipal($membership))->session;

        self::assertNotNull($session);

        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));
        app()->instance(RequirementCheck::class, new MeetNoRequirement);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart));

        $refreshed = $this->judgeAfter(
            $level,
            fn () => $this->elsewhere(function () use ($session): void {
                $result = $this->throughTheLink(new ExternalEvidence(['mfa'], null, $this->now));

                self::assertTrue($this->sessions('members')->reauthenticateExternally($session->record->getKey(), $result)->isIssued());
            }),
            fn (): bool => $this->sessions('members')->refresh((string) $session->tokens->refreshToken?->reveal())->isRefreshed(),
        );

        self::assertTrue($refreshed);
    }

    /**
     * A reauthentication through an external provider counts a step-up
     * committed after the caller's first read: a session whose tenant now asks
     * for a further factor, which the step-up meets, is issued its token.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnExternalReauthenticationCountsAStepUpCommittedMeanwhile(string $level): void
    {
        [$member, $membership] = $this->seedMember();

        $session = $this->sessions('members')->signInExternally($this->linkedResult($member, subject: 'subject-1'), self::asPrincipal($membership))->session;

        self::assertNotNull($session);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $reauthenticated = $this->judgeAfter(
            $level,
            fn () => $this->stepUpElsewhere($member, $session, 'factor-1'),
            fn (): ?FailureReason => $this->sessions('members')->reauthenticateExternally($session->record->getKey(), $this->throughTheLink())->reason,
        );

        self::assertNull($reauthenticated);
    }

    /**
     * A tenant's policy change counts a step-up committed after the caller's
     * first read: a session the new policy asks a further factor of, which the
     * step-up meets, records the version instead of being revoked.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAPolicyChangeCountsAStepUpCommittedMeanwhile(string $level): void
    {
        [$member, , $tenant] = $this->seedMember();

        $session = $this->signedIn('members', $member);

        $this->policy->requirement = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $revoked = $this->judgeAfter(
            $level,
            fn () => $this->stepUpElsewhere($member, $session, 'factor-1'),
            fn (): int => $this->sessions('members')->tenantPolicyChanged($tenant),
        );

        self::assertSame(0, $revoked);
        self::assertSame(['v2', null], [DB::table('authentication_sessions')->value('tenant_policy_version'), DB::table('authentication_sessions')->value('revoked_at')]);
    }

    /**
     * A tenant's policy change judges a session whose key another sign-in
     * reused after the caller's first read on the new session's own proofs and
     * provenance: a session established through the tenant's connection whose
     * key now holds a password sign-in is revoked as the policy's connection
     * requires, never kept on the earlier session's provenance.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAPolicyChangeJudgesAReusedKeyOnItsOwnProvenance(string $level): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signInExternally($this->linkedResult($member, subject: 'subject-1'), self::asPrincipal($membership))->session;

        self::assertNotNull($session);

        $this->policy->requirement = new TenantRequirement('v2', connections: ['connection-7']);

        $key = $session->record->getKey();

        $revoked = $this->judgeAfter(
            $level,
            fn () => $this->elsewhere(static function () use ($key): void {
                DB::table('authentication_sessions')->where('id', $key)->update(['generation' => (string) Str::uuid7(), 'sign_in_method' => 'password']);

                $row = SessionLookup::find($key);

                self::assertNotNull($row);

                ProofWriter::clear($row);
                ProofWriter::record($row, 'members', SignInProof::unattested('password', CarbonImmutable::now())->firstFactor());
            }),
            fn (): int => $this->sessions('members')->tenantPolicyChanged($tenant),
        );

        self::assertSame(1, $revoked);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * Register the guards, the chooser's among them.
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
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password']]]);
    }

    /**
     * Open the caller's transaction at the isolation level and read plainly
     * (the snapshot), have the other connection commit the change, then run the
     * judgement in the caller's transaction and commit it, returning what it
     * answered. Where the transaction reads a snapshot every read keeps
     * (PostgreSQL's REPEATABLE READ), the judgement fails to serialise first,
     * and the caller retries the whole transaction.
     *
     * @template TJudged
     *
     * @param  string  $level
     * @param  \Closure(): void  $change
     * @param  \Closure(): TJudged  $judge
     * @return TJudged
     *
     * @throws \Throwable
     */
    private function judgeAfter(string $level, \Closure $change, \Closure $judge): mixed
    {
        self::beginTransactionAt($level);

        self::assertGreaterThan(0, DB::table('authentication_proofs')->count());

        $change();

        if (self::readsASnapshot($level)) {
            self::assertSame('40001', self::failureOf($judge));

            self::beginTransactionAt($level);
        }

        $judged = $judge();

        DB::commit();

        return $judged;
    }

    /**
     * Run the work in the caller's open transaction, expecting it to fail to
     * serialise, roll the whole transaction back, and return the SQLSTATE it
     * failed with, or `null`: a pending action's own transaction rethrows the
     * database's error as it is, every other the concurrency error Laravel
     * raises inside a caller's transaction.
     *
     * @param  \Closure(): mixed  $work
     * @return ?string
     *
     * @throws \Throwable
     */
    private static function failureOf(\Closure $work): ?string
    {
        try {
            $work();
        } catch (DeadlockException $exception) {
            return (string) $exception->getPrevious()?->getCode();
        } catch (QueryException $exception) {
            return (string) $exception->getCode();
        } finally {
            DB::rollBack();
        }

        return null;
    }

    /**
     * Run the work on the other connection, as the default one, in a
     * transaction of its own that commits before this returns.
     *
     * @param  \Closure(): void  $work
     * @return void
     *
     * @throws \Throwable
     */
    private function elsewhere(\Closure $work): void
    {
        $manager = app(DatabaseManager::class);
        $default = $manager->getDefaultConnection();

        $manager->setDefaultConnection(self::OTHER);

        try {
            DB::transaction($work);
        } finally {
            $manager->setDefaultConnection($default);
        }
    }

    /**
     * Step the session up with the factor given, on the other connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  string  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpElsewhere(Identity $identity, SignedInSession $session, string $factor): void
    {
        $guard = (string) $session->record->getGuard();

        $this->elsewhere(function () use ($identity, $session, $guard, $factor): void {
            self::assertTrue($this->sessions($guard)->stepUp($this->proof($identity, $guard, $session->record->getKey(), $factor, Purpose::STEP_UP))->isIssued());
        });
    }

    /**
     * Void the session's proofs made with the factor on the other connection,
     * after its issuance guard, as a factor's removal voids them.
     *
     * @param  string  $guard
     * @param  mixed  $key
     * @param  string  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function voidElsewhere(string $guard, mixed $key, string $factor): void
    {
        $this->elsewhere(function () use ($guard, $key, $factor): void {
            $row = SessionLookup::lock($key);

            self::assertNotNull($row);

            IssuanceGuard::hold($row);

            self::assertSame(1, ProofWriter::void($row, $guard, $factor, $this->now));
        });
    }

    /**
     * A session the identity signed in to on the guard with its password.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard, Identity $identity): SignedInSession
    {
        $email   = $guard === 'api' ? 'ada@example.test' : 'member@example.test';
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);
        self::assertTrue($session->identity->getAuthIdentifier() === $identity->getAuthIdentifier());

        return $session;
    }

    /**
     * A session the identity signed in to pending a further factor and
     * activated with the factor given.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $factor
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function satisfied(string $guard, Identity $identity, string $factor): SignedInSession
    {
        $pending = $this->sessions($guard)->signIn('password', self::credentials());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $session = $this->sessions($guard)->satisfy($pending->credential->reveal(), $this->proof($identity, $guard, $pending->pending->id, $factor, Purpose::SIGN_IN))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * An accepted further factor's proof, made now with the factor given, for
     * the session and purpose given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $guard
     * @param  mixed  $key
     * @param  string  $factor
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    private function proof(Identity $identity, string $guard, mixed $key, string $factor, Purpose $purpose): ProofResult
    {
        return new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            $factor,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            $this->now,
            new ProofBinding($identity, $guard, $key, $purpose),
        );
    }

    /**
     * A result through the seeded member's link, the provider authenticating it
     * now, with the evidence given.
     *
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     */
    private function throughTheLink(?ExternalEvidence $evidence = null): ExternalResult
    {
        return new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now, evidence: $evidence);
    }

    /**
     * Persist a chooser with two memberships, each in an active tenant of its
     * own, so a sign-in that names no principal waits for a choice.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member      = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return [$member, $memberships[0]];
    }

    /**
     * A requirement check that is met only by accepted further factors of two
     * different factors among the subject's proofs.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\RequirementCheck
     */
    private static function twoFactorCheck(): RequirementCheck
    {
        return new class implements RequirementCheck {
            /**
             * Meet the requirement once two factors' proofs count.
             *
             * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
             * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
             * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
             *
             * @throws \InvalidArgumentException
             */
            #[\Override]
            public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
            {
                $factors = array_unique(array_map(static fn (RecordedProof $proof): ?string => $proof->factor, $subject->proofs(null, [ProofKind::ADDITIONAL_FACTOR], 10)));

                return new RequirementEvaluation(count($factors) >= 2 ? [] : $requirement->kinds());
            }
        };
    }
}
