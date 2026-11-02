<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\LevelRequirement;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Database\LockMarkingSQLiteGrammar;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\Fixtures\Sessions\TwoSecretSignIn;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\VerifiableChoosingMember;
use Tests\Integration\Fixtures\WideKeySession;
use Tests\TestCase;

/**
 * Tests of pending sessions through the session service: the actions a pending
 * credential allows, satisfying a further factor with a proof, choosing a
 * principal, discarding, and what a pending session refuses everywhere else,
 * against a real database through Laravel's guards and routes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PendingSessions::class)]
#[CoversClass(PendingEvaluation::class)]
#[CoversClass(SessionActivation::class)]
final class PendingSessionsTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessionRecords, InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, whose sign-ins wait for a choice of principal. */
    private const string CHOOSERS = 'choosers';

    /** @var string Guard over `VerifiableChoosingMember`, which requires a verified identifier. */
    private const string VERIFIED = 'verified';

    /** @var string Table of `WideKeySession`, whose keys are as long as the identifier columns hold. */
    private const string WIDE_KEY_TABLE = 'wide_key_sessions';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var bool Whether the bound factor policy asks for a further factor. */
    private bool $factorRequired = true;

    /** @var ?\Closure(\SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext): bool Answers the factor policy in place of the switch, when set. */
    private ?\Closure $factorAnswer = null;

    /** @var list<\SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext> Every context the factor policy was asked with, in order. */
    private array $factorContexts = [];

    /**
     * Freeze the clocks, create the tables, bind a factor policy the test
     * switches, and add a route behind the `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        $test = $this;

        app()->instance(AdditionalFactorPolicy::class, new readonly class ($test) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  \Tests\Feature\Sessions\PendingSessionsTest  $test
             */
            public function __construct(

                /** The test whose switch the policy answers with. */
                private PendingSessionsTest $test,
            ) {}

            /**
             * Answer as the test does.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return $this->test->isFactorRequiredFor($context) ? new Requirement(new RequirementPart) : new Requirement;
            }
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        Route::middleware('auth:api')->get('/me', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);
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
     * Record the context the factor policy is asked with, and answer with the
     * test's closure when it set one, else with its switch.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return bool
     */
    public function isFactorRequiredFor(AdditionalFactorContext $context): bool
    {
        $this->factorContexts[] = $context;

        return $this->factorAnswer === null ? $this->factorRequired : ($this->factorAnswer)($context);
    }

    /**
     * A credential waiting on a further factor allows exactly the five factor
     * actions and lists no principal; one waiting on a choice allows listing
     * and choosing principals, and lists the eligible ones; one waiting on a
     * factor and then a choice allows the factor actions only, and lists none
     * until the factor is met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialAllowsOnlyItsFirstRequirementsActions(): void
    {
        $this->seedIdentity();

        [$factor] = $this->pendingSignIn();

        $this->factorRequired = false;

        [$member, $first, $second] = $this->seedChooser();
        [$choice]                  = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $this->factorRequired = true;

        [$both] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        foreach (PendingAction::cases() as $action) {
            self::assertSame(in_array($action, PendingRequirement::MFA->actions(), true), $this->sessions()->pending($factor, $action) !== null, $action->value);
            self::assertSame(
                in_array($action, PendingRequirement::PRINCIPAL->actions(), true),
                $this->sessions(self::CHOOSERS)->pending($choice, $action) !== null,
                $action->value,
            );
            self::assertSame(in_array($action, PendingRequirement::MFA->actions(), true), $this->sessions(self::CHOOSERS)->pending($both, $action) !== null, $action->value);
        }

        $listed = $this->sessions(self::CHOOSERS)->pending($choice);

        self::assertNotNull($listed);
        self::assertTrue($member->is($listed->identity));
        self::assertNull($listed->principal);
        self::assertNull($listed->tenant);
        self::assertSame([PendingRequirement::PRINCIPAL], $listed->requires);
        self::assertSame([$first->getKey(), $second->getKey()], array_map(static fn (ChoosingMembership $membership): mixed => $membership->getKey(), $listed->principals));
        self::assertSame([], $this->sessions(self::CHOOSERS)->pending($both)?->principals);
        self::assertSame([], $this->sessions()->pending($factor)?->principals);
    }

    /**
     * Looking a pending session up reads it, with its owner, principal, method
     * and expiry, and changes nothing: it dispatches nothing and the credential
     * still works.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLookingAPendingSessionUpChangesNothing(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class]);

        $found = $this->sessions()->pending($credential);

        self::assertNotNull($found);
        self::assertSame($pending->id, $found->id);
        self::assertSame('api', $found->guard);
        self::assertTrue($identity->is($found->identity));
        self::assertTrue($identity->is($found->principal));
        self::assertSame('password', $found->method);
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), $found->expiresAt->getTimestamp());
        self::assertSame([], $this->recordedClasses());
        self::assertNotNull($this->sessions()->pending($credential));
    }

    /**
     * Rows of `[credential]` that cannot name a pending session, so are
     * rejected before any query: none, no secret, no key, or a key no session
     * can have.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedCredentials(): iterable
    {
        yield 'empty' => [''];
        yield 'no separator' => ['0190e1a4-0000-7000-8000-000000000001'];
        yield 'no secret' => ['0190e1a4-0000-7000-8000-000000000001.'];
        yield 'no key' => ['.secret'];
        yield 'a key too long' => [str_repeat('k', 256) . '.secret'];
        yield 'a key of another shape' => ['not-a-key.secret'];
    }

    /**
     * A malformed credential names nothing, for a look-up and for every action,
     * each refusal of which is `pending_invalid`, and none of them queries.
     *
     * @param  string  $credential
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedCredentials')]
    public function testAMalformedCredentialNamesNothing(string $credential): void
    {
        $identity = $this->seedIdentity();

        $this->pendingSignIn();

        $proof   = self::adapterProof($identity, 'api', '0190e1a4-0000-7000-8000-000000000001', Purpose::SIGN_IN);
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        self::assertNull($this->sessions()->pending($credential));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->satisfy($credential, $proof)->reason);
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->choose($credential, $identity)->reason);
        self::assertFalse($this->sessions()->discard($credential));
        self::assertSame([], $queries);
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
    }

    /**
     * A session key as long as the identifier columns hold, 255 characters,
     * names its pending session, however many bytes its characters take; a
     * credential whose key is a character longer names nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAKeyAsLongAsTheColumnsHoldNamesItsPendingSession(): void
    {
        $this->seedIdentity();

        self::createSessionRecordTable(self::WIDE_KEY_TABLE, stringKey: true);

        config()->set('authentication.session.model', WideKeySession::class);
        config()->set('authentication.session.table', self::WIDE_KEY_TABLE);

        try {
            [$credential, $pending] = $this->pendingSignIn();

            $key = IdentifierCoercion::stringify($pending->id) ?? '';

            self::assertSame(255, mb_strlen($key));
            self::assertGreaterThan(255, strlen($key));
            self::assertSame($key, IdentifierCoercion::stringify($this->sessions()->pending($credential)?->id));
            self::assertNull($this->sessions()->pending('é' . $credential));
        } finally {
            config()->set('authentication.session.table', 'authentication_sessions');

            Schema::dropIfExists(self::WIDE_KEY_TABLE);
        }
    }

    /**
     * A credential whose secret does not match, presented on another guard,
     * expired with its session, or whose session was revoked, activated or is
     * not pending, names no live pending session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyTheLiveCredentialOfTheGuardNamesThePendingSession(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();
        [$key, $secret]         = explode('.', $credential, 2);

        self::assertNull($this->sessions()->pending($key . '.' . strrev($secret)));
        self::assertNull($this->sessions('admin')->pending($credential));

        $this->clockAt($this->now->addMinutes(5));

        self::assertNull($this->sessions()->pending($credential));

        $this->clockAt($this->now->subSecond());

        self::assertNotNull($this->sessions()->pending($credential));

        DB::table('authentication_sessions')->update(['status' => 'active']);

        self::assertNull($this->sessions()->pending($credential));

        DB::table('authentication_sessions')->update(['status' => 'pending', 'revoked_at' => $this->now]);

        self::assertNull($this->sessions()->pending($credential));

        DB::table('authentication_sessions')->update(['revoked_at' => null]);

        self::assertTrue($this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN))->isSignedIn());
        self::assertNull($this->sessions()->pending($credential));
    }

    /**
     * A credential is no token, and no token is a credential: an access or
     * refresh token names no pending session, and the pending credential is
     * refused as a bearer token and as a refresh token, so one kind is never
     * accepted as another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialAndATokenAreNeverTakenForEachOther(): void
    {
        $this->seedIdentity();

        $this->factorRequired = false;

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $this->factorRequired = true;

        [$credential] = $this->pendingSignIn();

        self::assertNull($this->sessions()->pending($session->tokens->accessToken->reveal()));
        self::assertNull($this->sessions()->pending($session->tokens->refreshToken?->reveal()));
        self::assertFalse($this->sessions()->discard($session->tokens->refreshToken?->reveal()));

        $this->withHeaders(['Authorization' => 'Bearer ' . $credential])->getJson('/me')->assertUnauthorized();

        self::assertSame(FailureReason::TOKEN_INVALID, $this->sessions()->refresh($credential)->reason);
    }

    /**
     * Satisfying the further factor activates the pending session in place: the
     * same id, now active, waiting on nothing and holding no pending digest or
     * slots, with a pair whose access token authenticates and names the further
     * factor in `amr` and its time as `auth_time`, and whose refresh token
     * refreshes; the guard is bound, `SessionCreated` and `SignedIn` report the
     * sign-in, and the credential is consumed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSatisfyingTheFactorActivatesTheSessionInPlace(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();

        $this->clockAt($this->now->addMinute());
        $this->recordEvents([SessionCreated::class, SignedIn::class, Login::class]);

        $guard  = $this->freshGuard();
        $result = self::sessionsOf($guard)->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN));

        self::assertTrue($result->isSignedIn());
        self::assertNull($result->credential);

        $session = $result->session;

        self::assertNotNull($session);
        self::assertSame($pending->id, $session->record->getKey());
        self::assertSame([SessionCreated::class, SignedIn::class, Login::class], $this->recordedClasses());
        self::assertSame($session->record, $guard->session());

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::ACTIVE, $row->getStatus());
        self::assertSame([], $row->getRequires());
        self::assertNull($row->getPendingKey());
        self::assertNull($row->attempt_windows);
        self::assertNotNull($row->getRefreshKey());
        self::assertSame($this->now->addDays(30)->getTimestamp(), $row->getIdleExpiresAt()?->getTimestamp());
        self::assertSame(2, SessionProof::query()->count());

        $claims = Auth::manager()->jwt('api')->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertContains('otp', $claims['amr']);
        self::assertSame($this->now->getTimestamp(), $claims['auth_time']);

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me')->assertOk()->assertJson(['session' => $pending->id]);

        self::assertTrue($this->sessions()->refresh($session->tokens->refreshToken?->reveal())->isRefreshed());
        self::assertNull($this->sessions()->pending($credential));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN))->reason);
    }

    /**
     * The pending credential a sign-in returned is taken as the `Secret` it was
     * returned as, as its revealed string is: looked up, satisfied, chosen with
     * and discarded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePendingCredentialIsTakenAsTheSecretItWasReturnedAs(): void
    {
        [$member, $first] = $this->seedChooser();

        $signIn = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'));
        $again  = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'));

        self::assertNotNull($signIn->pending);
        self::assertNotNull($signIn->credential);
        self::assertNotNull($again->credential);

        $credential = $signIn->credential;
        $proof      = self::adapterProof($member, self::CHOOSERS, $signIn->pending->id, Purpose::SIGN_IN);

        self::assertSame($signIn->pending->id, $this->sessions(self::CHOOSERS)->pending($credential)?->id);
        self::assertTrue($this->sessions(self::CHOOSERS)->satisfy($credential, $proof)->isPending());
        self::assertTrue($this->sessions(self::CHOOSERS)->choose($credential, $first)->isSignedIn());
        self::assertTrue($this->sessions(self::CHOOSERS)->discard($again->credential));
        self::assertNull($this->sessions(self::CHOOSERS)->pending($again->credential));
    }

    /**
     * A session waiting on a factor and then a choice moves on to the choice
     * once the factor is satisfied: still pending, with the same credential,
     * which now lists the principals and allows the choice, and no token; the
     * choice then activates it as the principal, in its own tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSatisfyingTheFactorMovesOnToTheChoice(): void
    {
        [$member, $first] = $this->seedChooser();

        [$credential, $pending] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], $pending->requires);

        $moved = $this->sessions(self::CHOOSERS)->satisfy($credential, self::adapterProof($member, self::CHOOSERS, $pending->id, Purpose::SIGN_IN));

        self::assertTrue($moved->isPending());
        self::assertNull($moved->credential);
        self::assertNull($moved->session);
        self::assertNotNull($moved->pending);
        self::assertSame([PendingRequirement::PRINCIPAL], $moved->pending->requires);
        self::assertCount(2, $moved->pending->principals);
        self::assertSame([PendingRequirement::PRINCIPAL], Session::query()->sole()->getRequires());
        self::assertNotNull($this->sessions(self::CHOOSERS)->pending($credential, PendingAction::CHOOSE_PRINCIPAL));

        $chosen = $this->sessions(self::CHOOSERS)->choose($credential, $first);

        self::assertTrue($chosen->isSignedIn());
        self::assertTrue($first->is($chosen->session?->principal));

        $row = Session::query()->sole();

        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($first->tenant_id), $row->getTenantId());
    }

    /**
     * A further factor is not taken while only the choice is outstanding, and a
     * choice is not taken while a factor is: each is refused as
     * `pending_action_not_allowed`, reported, and leaves the session pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActionTheFirstRequirementDoesNotAllowIsRefused(): void
    {
        [$member, $first] = $this->seedChooser();

        [$both, $waiting] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $this->factorRequired = false;

        [$choice, $choosing] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::PENDING_ACTION_NOT_ALLOWED, $this->sessions(self::CHOOSERS)->choose($both, $first)->reason);
        self::assertSame(
            FailureReason::PENDING_ACTION_NOT_ALLOWED,
            $this->sessions(self::CHOOSERS)->satisfy($choice, self::adapterProof($member, self::CHOOSERS, $choosing->id, Purpose::SIGN_IN))->reason,
        );
        self::assertSame(
            [FailureReason::PENDING_ACTION_NOT_ALLOWED, FailureReason::PENDING_ACTION_NOT_ALLOWED],
            array_map(static fn (object $event): ?FailureReason => $event instanceof AuthenticationFailed ? $event->reason : null, $this->recorded),
        );
        self::assertSame(2, Session::query()->where('status', 'pending')->count());
        self::assertSame(2, SessionProof::query()->count());
        $still = $this->sessions(self::CHOOSERS)->pending($both);

        self::assertNotNull($still);
        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], $still->requires);
        self::assertSame($waiting->id, $still->id);
    }

    /**
     * A principal that is not one of the identity's, resolved through the
     * hinted path as that very one, is refused as `principal_mismatch`, and the
     * session stays pending for another choice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingAPrincipalThatIsNotTheIdentitysIsRefused(): void
    {
        $this->factorRequired = false;

        [, $first] = $this->seedChooser();

        $other  = ChoosingMember::query()->create(['email' => 'other@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $theirs = ChoosingMembership::query()->create(['identity_id' => $other->getKey(), 'tenant_id' => $first->tenant_id]);

        [$credential] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $this->sessions(self::CHOOSERS)->choose($credential, $theirs)->reason);
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
        self::assertTrue($this->sessions(self::CHOOSERS)->choose($credential, $first)->isSignedIn());
    }

    /**
     * A principal whose tenant was deactivated while the session waited is
     * refused when chosen, with the session left pending for another choice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingAPrincipalWhoseTenantIsInactiveIsRefused(): void
    {
        $this->factorRequired = false;

        [, $first, $second] = $this->seedChooser();

        [$credential] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        self::assertSame(FailureReason::TENANT_INACTIVE, $this->sessions(self::CHOOSERS)->choose($credential, $first)->reason);
        self::assertTrue($this->sessions(self::CHOOSERS)->choose($credential, $second)->isSignedIn());
    }

    /**
     * A choice after which the identity's factor policy now asks for a further
     * factor records the principal and its tenant and waits for the factor with
     * the same credential, the session it describes holding what was written as
     * stored; satisfying it then activates the session as that principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceWaitsForAFactorTheIdentityNowOwes(): void
    {
        $this->factorRequired = false;

        [$member, $first] = $this->seedChooser();

        [$credential, $pending] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $this->factorRequired = true;

        $waiting = $this->sessions(self::CHOOSERS)->choose($credential, $first);

        self::assertTrue($waiting->isPending());
        self::assertSame([PendingRequirement::MFA], $waiting->pending?->requires);
        self::assertTrue($first->is($waiting->pending->principal));

        $record = $waiting->pending->session;

        self::assertInstanceOf(Session::class, $record);
        self::assertSame([PendingRequirement::MFA], $record->getRequires());
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $record->getRawOriginal('principal_id'));
        self::assertSame(IdentifierCoercion::stringify($first->tenant_id), $record->getTenantId());
        self::assertFalse($record->isDirty());

        $row = Session::query()->sole();

        self::assertSame([PendingRequirement::MFA], $row->getRequires());
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($first->tenant_id), $row->getTenantId());

        $active = $this->sessions(self::CHOOSERS)->satisfy($credential, self::adapterProof($member, self::CHOOSERS, $pending->id, Purpose::SIGN_IN));

        self::assertTrue($active->isSignedIn());
        self::assertTrue($first->is($active->session?->principal));
    }

    /**
     * Each check a sign-in made is made again when the pending session is acted
     * on, so what changed while it waited refuses the action and leaves the
     * session pending: an identity deactivated, a method the application no
     * longer allows, a recorded principal whose tenant was deactivated.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGateRefusesWhatChangedWhileTheSessionWaited(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();

        $proof = self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN);

        IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->sessions()->satisfy($credential, $proof)->reason);

        IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => true]);
        config()->set('auth.guards.api.application.methods', ['sso']);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->satisfy($credential, $proof)->reason);

        config()->set('auth.guards.api.application.methods', ['password']);

        [$member, $membership, $tenant] = $this->seedMember();

        [$memberCredential, $memberPending] = $this->pendingSignIn('members', 'member@example.test');

        $tenant->forceFill(['is_active' => false])->save();

        self::assertSame(
            FailureReason::TENANT_INACTIVE,
            $this->sessions('members')->satisfy($memberCredential, self::adapterProof($member, 'members', $memberPending->id, Purpose::SIGN_IN))->reason,
        );
        self::assertTrue($membership->is($memberPending->principal));
        self::assertSame(2, Session::query()->where('status', 'pending')->count());
        self::assertSame(2, SessionProof::query()->count());
        self::assertTrue($this->sessions()->satisfy($credential, $proof)->isSignedIn());
    }

    /**
     * A sign-in that proved the session its client holds supersedes it only
     * when it first activates: the proven session stays live while the new one
     * waits, and is revoked as `superseded`, reported before the sign-in's
     * events, when it activates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProvenSessionIsSupersededOnlyOnActivation(): void
    {
        $identity = $this->seedIdentity();

        $this->factorRequired = false;

        $first = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($first);

        $this->factorRequired = true;

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());
        $result  = $this->sessions()->signIn('password', self::credentials(), $context);

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertNull(DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_at'));
        self::assertSame($first->record->getKey(), DB::table('authentication_sessions')->where('id', $result->pending->id)->value('supersedes_session_id'));

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        self::assertTrue($this->sessions()->satisfy($result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN))->isSignedIn());
        self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(RevocationReason::SUPERSEDED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $result->pending->id)->value('supersedes_session_id'));
    }

    /**
     * A proven session that rotated while the new one waited is not superseded:
     * the new one still activates, and the proven one stays live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenSessionThatChangedIsNotSuperseded(): void
    {
        $identity = $this->seedIdentity();

        $this->factorRequired = false;

        $first = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($first);

        $this->factorRequired = true;

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());
        $result  = $this->sessions()->signIn('password', self::credentials(), $context);

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertTrue($this->sessions()->refresh($first->tokens->refreshToken?->reveal())->isRefreshed());
        self::assertTrue($this->sessions()->satisfy($result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN))->isSignedIn());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * Rows of `[change, still proven]`: a change to the proven session while
     * the sign-in waits, and whether the factor policy is still told of it.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideChangesToTheProvenSession(): iterable
    {
        yield 'unchanged' => [[], true];
        yield 'revoked' => [['revoked_at' => '2026-04-06 11:00:00', 'revoked_reason' => 'revoked'], false];
        yield 'rotated' => [['refresh_key' => hash('sha256', 'rotated')], false];
        yield 'another guard' => [['guard' => 'members'], false];
        yield 'another owner' => [['authenticatable_id' => '999999'], false];
        yield 'returned to pending' => [['status' => 'pending', 'requires' => '["mfa"]'], false];
    }

    /**
     * At activation the factor policy is told of the session the sign-in's
     * client proved it holds only while that session is as it was proven: of
     * this guard and owner, active, unrevoked and holding the digest it was
     * proven against. Only then is it superseded.
     *
     * @param  array<string, mixed>  $change
     * @param  bool  $proven
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesToTheProvenSession')]
    public function testTheFactorPolicyIsToldOfTheProvenSessionOnlyWhileItIsAsProven(array $change, bool $proven): void
    {
        $identity = $this->seedIdentity();

        $this->factorRequired = false;

        $first = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($first);

        $this->factorRequired = true;

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken?->reveal());
        $result  = $this->sessions()->signIn('password', self::credentials(), $context);

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        if ($change !== []) {
            DB::table('authentication_sessions')->where('id', $first->record->getKey())->update($change);
        }

        $asked = count($this->factorContexts);

        self::assertTrue($this->sessions()->satisfy($result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN))->isSignedIn());
        self::assertCount($asked + 1, $this->factorContexts);
        self::assertSame($proven ? $first->record->getKey() : null, $this->factorContexts[$asked]->provenSession?->getSessionIdentifier());

        $reason = DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason');

        self::assertSame($proven ? 'superseded' : $change['revoked_reason'] ?? null, $reason);
    }

    /**
     * At activation the factor policy is asked as the sign-in was: about the
     * first factor's proof, the client the sign-in came from and the name and
     * platform it gave, as the session recorded them, never about the client
     * acting on the pending session, whose address only becomes the session's
     * last use.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorPolicyIsAskedAtActivationAsTheSignInWas(): void
    {
        $identity = $this->seedIdentity();

        $origin = new SignInContext(new ClientContext('192.0.2.10', 'Origin/1.0'), 'Work laptop', 'macOS');
        $result = $this->sessions()->signIn('password', self::credentials(), $origin);

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        app()->instance('request', Request::create('/satisfy', 'POST', server: ['REMOTE_ADDR' => '198.51.100.99', 'HTTP_USER_AGENT' => 'Completer/2.0']));

        Auth::forgetGuards();

        $before = count($this->factorContexts);

        self::assertTrue(Auth::sessions('api')->satisfy($result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN))->isSignedIn());
        self::assertCount($before + 1, $this->factorContexts);

        $asked = $this->factorContexts[$before];

        self::assertSame('api', $asked->application);
        self::assertTrue($identity->is($asked->identity));
        self::assertSame('password', $asked->firstFactor->method);
        self::assertSame(ProofKind::FIRST_FACTOR, $asked->firstFactor->kind);
        self::assertSame(ChannelKind::PASSWORD, $asked->firstFactor->channel->kind);
        self::assertSame('192.0.2.10', $asked->client->ip);
        self::assertSame('Origin/1.0', $asked->client->userAgent);
        self::assertSame('Work laptop', $asked->clientName);
        self::assertSame('macOS', $asked->platform);
        self::assertNull($asked->provenSession);
        self::assertSame('198.51.100.99', Session::query()->sole()->getRawOriginal('last_used_ip'));
    }

    /**
     * Rows of `[factor required without the proven session, activates]`.
     *
     * @return iterable<string, array{0: bool, 1: bool}>
     */
    public static function provideAnswersWithoutTheProvenSession(): iterable
    {
        yield 'a factor is owed without it' => [true, false];
        yield 'no factor is owed either way' => [false, true];
    }

    /**
     * A choice whose proven session changes after the factor policy waived the
     * factor for it, and before the activation could supersede it, is judged
     * again without it, the factor policy asked again: the session waits on the
     * factor, the chosen principal and tenant recorded, when the policy now
     * asks for one, and otherwise activates superseding nothing. The changed
     * session stays as its change left it either way.
     *
     * @param  bool  $required
     * @param  bool  $activates
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAnswersWithoutTheProvenSession')]
    public function testAChoiceWhoseProvenSessionChangesBeforeItIsSupersededIsJudgedAgain(bool $required, bool $activates): void
    {
        [, $first] = $this->seedChooser();

        $this->factorRequired = false;

        $client = new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT);
        $active = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'), new SignInContext($client, principal: $first))->session;

        self::assertNotNull($active);

        $context = new SignInContext($client, refreshToken: $active->tokens->refreshToken?->reveal());
        $result  = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'), $context);

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertSame([PendingRequirement::PRINCIPAL], $result->pending->requires);

        $proven  = $active->record->getKey();
        $rotated = hash('sha256', 'rotated');

        $before             = count($this->factorContexts);
        $this->factorAnswer = static function (AdditionalFactorContext $context) use ($proven, $rotated, $required): bool {

            if ($context->provenSession === null) {
                return $required;
            }

            DB::table('authentication_sessions')->where('id', $proven)->update(['refresh_key' => $rotated]);

            return false;
        };

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        $chosen = $this->sessions(self::CHOOSERS)->choose($result->credential->reveal(), $first);

        $told = array_map(static fn (AdditionalFactorContext $asked): mixed => $asked->provenSession?->getSessionIdentifier(), array_slice($this->factorContexts, $before));

        self::assertSame([$proven, null], $told);
        self::assertSame($activates, $chosen->isSignedIn());
        self::assertSame($activates ? [SessionCreated::class, SignedIn::class] : [], $this->recordedClasses());

        $row = Session::query()->whereKey($result->pending->id)->firstOrFail();

        self::assertSame($activates ? SessionStatus::ACTIVE : SessionStatus::PENDING, $row->getStatus());
        self::assertSame($activates ? [] : [PendingRequirement::MFA], $row->getRequires());
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($first->tenant_id), $row->getTenantId());
        self::assertNull(DB::table('authentication_sessions')->where('id', $proven)->value('revoked_at'));
        self::assertSame($rotated, DB::table('authentication_sessions')->where('id', $proven)->value('refresh_key'));
    }

    /**
     * A method that checks two secrets counts two checks against the account,
     * and its pending session gives both slots back once it activates, as a
     * sign-in that starts its session at once does: satisfying further factors
     * never uses up the account's limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationGivesBackEverySlotItsMethodTookOnTheAccount(): void
    {
        $identity = $this->seedIdentity();
        $input    = [...self::credentials(), 'pin' => TwoSecretSignIn::PIN];

        app(SignInMethodManager::class)->extend('two_secrets', fn (): TwoSecretSignIn => new TwoSecretSignIn);
        config()->set('auth.guards.api.application.methods', ['two_secrets']);

        $hits = static fn (): array => [
            self::counterHits('api', 'sign_in', 'per_identifier', 'ada@example.test'),
            self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)),
        ];

        for ($signIn = 1; $signIn <= 6; $signIn++) {

            $result = $this->sessions()->signIn('two_secrets', $input);

            self::assertNotNull($result->pending, 'Expected a pending session; got ' . self::describe($result));
            self::assertNotNull($result->credential);
            self::assertSame([1, 2], $hits());
            self::assertTrue($this->sessions()->satisfy($result->credential->reveal(), self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN))->isSignedIn());
            self::assertSame([0, 0], $hits());
        }
    }

    /**
     * Under Eloquent strict mode, which prevents lazy loading on models read
     * together, a pending session is looked up with its principals listed, the
     * choice is made and recorded, the session recording that principal and its
     * tenant is looked up again, and its factor activates it: each principal's
     * tenant is read as stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionIsActedOnUnderEloquentStrictMode(): void
    {
        $this->factorRequired = false;

        [$member, $first] = $this->seedChooser();

        [$credential, $pending] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        Model::preventLazyLoading();

        try {
            self::assertCount(2, $this->sessions(self::CHOOSERS)->pending($credential)->principals ?? []);

            $this->factorRequired = true;

            self::assertTrue($this->sessions(self::CHOOSERS)->choose($credential, $first)->isPending());

            $recorded = $this->sessions(self::CHOOSERS)->pending($credential, PendingAction::SEND_CODE);

            self::assertNotNull($recorded);
            self::assertTrue($first->is($recorded->principal));
            self::assertSame(IdentifierCoercion::stringify($first->tenant_id), IdentifierCoercion::stringify($recorded->tenant?->getTenantIdentifier()));

            $active = $this->sessions(self::CHOOSERS)->satisfy($credential, self::adapterProof($member, self::CHOOSERS, $pending->id, Purpose::SIGN_IN));
        } finally {
            Model::preventLazyLoading(false);
        }

        self::assertTrue($active->isSignedIn());
        self::assertTrue($first->is($active->session?->principal));
    }

    /**
     * A guard that requires a verified identifier offers no choice to an
     * identity whose identifier is unverified: the sign-in fails as
     * `identifier_unverified` with nothing written. Once it is verified the
     * choice is offered; an identifier unverified again while the session waits
     * names nothing to act on, and the choice is refused for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnverifiedIdentifierIsOfferedNoChoice(): void
    {
        $this->factorRequired = false;

        Schema::table('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->boolean('email_verified')->default(false);
        });

        $member = VerifiableChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {

            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        $refused = $this->sessions(self::VERIFIED)->signIn('password', self::credentials('chooser@example.test'));

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused->reason);
        self::assertSame(0, Session::query()->count());

        $member->markIdentifierAsVerified('email', $member->email);

        [$credential] = $this->pendingSignIn(self::VERIFIED, 'chooser@example.test');

        self::assertCount(2, $this->sessions(self::VERIFIED)->pending($credential)->principals ?? []);

        $member->forceFill(['email_verified' => false])->save();

        $chosen = ChoosingMembership::query()->where('identity_id', $member->getKey())->firstOrFail();

        self::assertNull($this->sessions(self::VERIFIED)->pending($credential));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->sessions(self::VERIFIED)->choose($credential, $chosen)->reason);
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
    }

    /**
     * Discarding a pending session revokes it as `signed_out`, reported once,
     * so its credential names nothing afterwards; a credential that names no
     * live pending session discards nothing and reports nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDiscardingRevokesThePendingSession(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();

        $this->recordEvents([SessionRevoked::class, AuthenticationFailed::class]);

        self::assertTrue($this->sessions()->discard($credential));
        self::assertFalse($this->sessions()->discard($credential));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::SIGNED_OUT, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(IdentifierCoercion::stringify($pending->id), $this->recordedEvent(SessionRevoked::class)->context->sessionId);
        self::assertSame('signed_out', Session::query()->sole()->getRevokedReason());
        self::assertNull($this->sessions()->pending($credential));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN))->reason);
    }

    /**
     * Looking a pending session up reads its row without a lock, while every
     * action on it (satisfying, choosing, discarding) reads it locked for
     * update first, so a revocation or another action waits for it. On SQLite,
     * which takes no row lock, the lock is written into the SQL as a comment.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAnActionLocksThePendingSessionsRow(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();

        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSQLiteGrammar($connection));
        }

        /** @var \ArrayObject<int, bool> $locks Whether each read of a session row locked it, in order. */
        $locks = new \ArrayObject;

        $connection->listen(static function (QueryExecuted $query) use ($locks): void {
            if (!str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'authentication_sessions')) {
                return;
            }

            $locks[] = str_contains(strtolower($query->sql), 'for update');
        });

        $this->sessions()->pending($credential);

        self::assertNotSame([], $locks->getArrayCopy());
        self::assertNotContains(true, $locks->getArrayCopy());

        $actions = [
            'satisfy' => fn (): mixed => $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::STEP_UP)),
            'choose'  => fn (): mixed => $this->sessions()->choose($credential, $identity),
            'discard' => fn (): mixed => $this->sessions()->discard($credential),
        ];

        foreach ($actions as $name => $action) {
            $locks->exchangeArray([]);

            $action();

            self::assertTrue($locks[0] ?? false, $name . ' read the pending session without a lock first.');
        }
    }

    /**
     * A pending session is no active session: the list of the identity's
     * sessions leaves it out, and a session that is made pending refuses its
     * access token on every request (`session_pending`, a 401) and its refresh
     * token as `session_pending`, not as a replay, so the session is not
     * revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionIsListedNowhereAndAuthenticatesNothing(): void
    {
        $identity = $this->seedIdentity();

        $this->factorRequired = false;

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $this->factorRequired = true;

        $this->pendingSignIn();

        self::assertSame(
            [IdentifierCoercion::stringify($session->record->getKey())],
            array_map(static fn (SessionSummary $summary): string => $summary->id, $this->sessions()->sessions($identity)->items()),
        );

        DB::table('authentication_sessions')->where('id', $session->record->getKey())->update(['status' => 'pending', 'requires' => '["mfa"]']);

        $this->recordEvents([AuthenticationFailed::class]);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken->reveal()])->getJson('/me')->assertUnauthorized();

        self::assertSame(FailureReason::SESSION_PENDING, $this->recordedEvent(AuthenticationFailed::class)->reason);

        $refused = $this->sessions()->refresh($session->tokens->refreshToken?->reveal());

        self::assertSame(FailureReason::SESSION_PENDING, $refused->reason);
        self::assertNull(DB::table('authentication_sessions')->where('id', $session->record->getKey())->value('revoked_at'));
        self::assertSame([], $this->sessions()->sessions($identity)->items());
    }

    /**
     * A satisfied factor that leaves the session waiting on a choice with no
     * principal left to choose from is refused for the reason the last was
     * refused, after the proof was stored, and the refusal rolls everything
     * back: the session still waits on the factor and the choice, and the proof
     * is gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorThatLeavesNoPrincipalToChooseIsRefusedAndStoresNothing(): void
    {
        [$member] = $this->seedChooser();

        [$credential, $pending] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        ActivatableTenant::query()->update(['is_active' => false]);

        $proofs = SessionProof::query()->count();

        $this->recordEvents([AuthenticationFailed::class, SessionCreated::class]);

        $refused = $this->sessions(self::CHOOSERS)->satisfy($credential, self::adapterProof($member, self::CHOOSERS, $pending->id, Purpose::SIGN_IN));

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::TENANT_INACTIVE, $refused->reason);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($proofs, SessionProof::query()->count());

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::PENDING, $row->getStatus());
        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], $row->getRequires());
    }

    /**
     * A satisfied factor whose recorded tenant now requires a connection the
     * session was not established through is refused as `sso_required` after
     * the proof was stored, and the refusal rolls the proof back with
     * everything else.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorWhoseTenantNowRequiresAConnectionIsRefusedAndStoresNothing(): void
    {
        [$member] = $this->seedMember();

        [$credential, $pending] = $this->pendingSignIn('members', 'member@example.test');

        $proofs = SessionProof::query()->count();

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', connections: ['conn-a'])));

        $refused = $this->sessions('members')->satisfy($credential, self::adapterProof($member, 'members', $pending->id, Purpose::SIGN_IN));

        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertSame($proofs, SessionProof::query()->count());
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
        self::assertNotNull($this->sessions('members')->pending($credential));
    }

    /**
     * A pending session names what its authentication still falls short of, the
     * strictest of the identity's requirement and its tenant's while each is
     * unmet, with the first factor it signed in with and its counting proofs,
     * newest first; a factor the check does not find enough leaves it pending
     * and short of the same, and one it finds enough activates it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePendingSessionNamesWhatItsAuthenticationStillFallsShortOf(): void
    {
        [$member] = $this->seedMember();

        app()->instance(AdditionalFactorPolicy::class, new readonly class implements AdditionalFactorPolicy {
            /**
             * Ask for a further factor within five minutes.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart(300));
            }
        });
        $tenantFactor = new Requirement(minimumLevel: new LevelRequirement(AssuranceLevel::AAL2));

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', $tenantFactor)));
        app()->instance(RequirementCheck::class, new MeetNoRequirement);

        $short = [RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::MINIMUM_LEVEL];

        [$credential, $pending] = $this->pendingSignIn('members', 'member@example.test');

        self::assertSame($short, $pending->requirement->kinds());

        $looked = $this->sessions('members')->pending($credential);
        $stored = SessionProof::query()->sole();

        self::assertNotNull($looked);
        self::assertSame($short, $looked->requirement->kinds());
        self::assertSame(300, $looked->requirement->additionalVerification?->maxAgeSeconds);
        self::assertSame($stored->getKey(), $looked->firstFactor->id);
        self::assertSame([$stored->getKey()], array_column($looked->proofs(), 'id'));
        self::assertSame([], $looked->proofs(null, [ProofKind::ADDITIONAL_FACTOR]));

        $this->clockAt($this->now->addMinute());

        $result = $this->sessions('members')->satisfy($credential, self::adapterProof($member, 'members', $pending->id, Purpose::SIGN_IN));

        self::assertTrue($result->isPending());
        self::assertSame($short, $result->pending?->requirement->kinds());
        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], array_column($result->pending->proofs(), 'kind'));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR], array_column($result->pending->proofs($this->now), 'kind'));

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $this->clockAt($this->now->addMinute());

        self::assertTrue($this->sessions('members')->satisfy($credential, self::adapterProof($member, 'members', $pending->id, Purpose::SIGN_IN))->isSignedIn());
    }

    /**
     * While only the choice of principal is outstanding the pending session
     * names no requirement, and looking it up asks no factor policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceAloneNamesNoRequirementAndAsksNoFactorPolicy(): void
    {
        $this->seedChooser();

        $this->factorRequired = false;

        [$choice] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $asked  = count($this->factorContexts);
        $looked = $this->sessions(self::CHOOSERS)->pending($choice);

        self::assertNotNull($looked);
        self::assertTrue($looked->requirement->isEmpty());
        self::assertSame(ProofKind::FIRST_FACTOR, $looked->firstFactor->kind);
        self::assertCount($asked, $this->factorContexts);
    }

    /**
     * A failure while a satisfied factor is judged, after the proof was stored,
     * is thrown on as it was raised, and rolls back everything the call wrote:
     * no transaction is left open, the proof is gone, nothing is reported, and
     * the session waits on the factor exactly as it did, so the same credential
     * activates it once the failure clears.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureWhileAFactorIsJudgedRollsEverythingBackAndIsThrownOn(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();

        $failure = new \RuntimeException('The factor policy cannot be reached.');
        $level   = DB::transactionLevel();
        $proofs  = SessionProof::query()->count();
        $row     = (array) DB::table('authentication_sessions')->where('id', $pending->id)->sole();
        $stored  = null;

        $this->factorAnswer = static function () use ($failure, &$stored): never {

            $stored = SessionProof::query()->count();

            throw $failure;
        };

        $this->recordEvents([AuthenticationFailed::class, SessionCreated::class, SignedIn::class]);

        try {
            $this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN));

            self::fail('The factor policy\'s failure was not thrown on.');
        } catch (\RuntimeException $thrown) {
            self::assertSame($failure, $thrown);
        }

        self::assertSame($proofs + 1, $stored);
        self::assertSame($level, DB::transactionLevel());
        self::assertSame($proofs, SessionProof::query()->count());
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($row, (array) DB::table('authentication_sessions')->where('id', $pending->id)->sole());

        $this->factorAnswer   = null;
        $this->factorRequired = false;

        self::assertTrue($this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN))->isSignedIn());
        self::assertSame($proofs + 1, SessionProof::query()->count());
    }

    /**
     * The pre-action seam answers nothing for a session the gate would refuse,
     * so no code is sent and no enrolment begun for one that can never
     * activate: its identity deactivated, or its method no longer allowed. Once
     * neither holds, it answers again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePreActionSeamAnswersNothingForASessionTheGateWouldRefuse(): void
    {
        $identity = $this->seedIdentity();

        [$credential] = $this->pendingSignIn();

        self::assertNotNull($this->sessions()->pending($credential, PendingAction::SEND_CODE));

        IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        self::assertNull($this->sessions()->pending($credential, PendingAction::SEND_CODE));
        self::assertNull($this->sessions()->pending($credential));

        IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => true]);
        config()->set('auth.guards.api.application.methods', ['sso']);

        self::assertNull($this->sessions()->pending($credential, PendingAction::START_BOOTSTRAP_ENROLLMENT));

        config()->set('auth.guards.api.application.methods', ['password']);

        self::assertNotNull($this->sessions()->pending($credential, PendingAction::SEND_CODE));
    }

    /**
     * Under an enforced morph map, a choice records the principal by its alias,
     * and its `SignedIn` names the identity and principal by their aliases and
     * the tenant the map leaves out by its class, with its identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceUnderAnEnforcedMorphMapRecordsAnUnmappedTenantByItsClass(): void
    {
        [, $first] = $this->seedChooser();

        $this->factorRequired = false;

        Relation::enforceMorphMap(['chooser' => ChoosingMember::class, 'membership' => ChoosingMembership::class]);

        try {
            [$credential] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

            $this->recordEvents([SignedIn::class]);

            self::assertTrue($this->sessions(self::CHOOSERS)->choose($credential, $first)->isSignedIn());

            $context = $this->recordedEvent(SignedIn::class)->context;

            self::assertSame('chooser', $context->identityType);
            self::assertSame('membership', $context->principalType);
            self::assertSame(ActivatableTenant::class, $context->tenantType);
            self::assertSame(IdentifierCoercion::stringify($first->tenant_id), $context->tenantId);
            self::assertSame('membership', DB::table('authentication_sessions')->value('principal_type'));
        } finally {
            Relation::requireMorphMap(false);
            Relation::morphMap([], false);
        }
    }

    /**
     * Rows of `[change]` after which the gate refuses the principal a pending
     * session records, or the active tenant it records for it, although the
     * credential still names the session.
     *
     * @return iterable<string, array{0: \Closure(mixed): void}>
     */
    public static function provideRefusalsOfTheRecordedContext(): iterable
    {
        yield 'the application refuses the principal' => [static function (): void {
            app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (): bool => true));
        }];

        yield 'the principal\'s tenant is inactive' => [static function (): void {
            ActivatableTenant::query()->update(['is_active' => false]);
        }];

        yield 'the recorded tenant no longer resolves' => [static function (mixed $session): void {
            DB::table('authentication_sessions')->where('id', $session)->update(['tenant_id' => '999999']);
        }];

        yield 'the principal may no longer act in the recorded tenant' => [static function (mixed $session): void {
            $elsewhere = ActivatableTenant::query()->create(['name' => 'Elsewhere', 'is_active' => true]);
            $tree      = new DescendantTenants;

            app()->instance(TenantAccess::class, $tree);
            app()->instance(TenantResolver::class, $tree);

            DB::table('authentication_sessions')->where('id', $session)->update(['tenant_id' => IdentifierCoercion::stringify($elsewhere->getKey())]);
        }];
    }

    /**
     * The pre-action seam answers nothing for a session whose recorded
     * principal or active tenant the gate would refuse, as satisfying it is
     * refused, so no code is sent and no enrolment begun for it.
     *
     * @param  \Closure(mixed): void  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusalsOfTheRecordedContext')]
    public function testThePreActionSeamAnswersNothingForARecordedContextTheGateWouldRefuse(\Closure $change): void
    {
        [$member, , $tenant] = $this->seedMember();

        [$credential, $pending] = $this->pendingSignIn('members', 'member@example.test');

        $described = $this->sessions('members')->pending($credential, PendingAction::SEND_CODE)?->tenant;

        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), IdentifierCoercion::stringify($described?->getTenantIdentifier()));

        $change($pending->id);

        self::assertNull($this->sessions('members')->pending($credential, PendingAction::SEND_CODE));
        self::assertNull($this->sessions('members')->pending($credential));
        self::assertTrue($this->sessions('members')->satisfy($credential, self::adapterProof($member, 'members', $pending->id, Purpose::SIGN_IN))->isFailed());
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
    }

    /**
     * Rows of `[change]` that leave a pending credential naming nothing.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\ActivatableTenantMember, \Tests\Integration\Fixtures\ActivatableTenantMembership): void}>
     */
    public static function provideChangesThatEndTheCredential(): iterable
    {
        yield 'the owner is gone' => [static function (ActivatableTenantMember $member): void {
            DB::table('activatable_tenant_members')->where('id', $member->getKey())->delete();
        }];

        yield 'the principal is gone' => [static function (ActivatableTenantMember $member, ActivatableTenantMembership $membership): void {
            DB::table('activatable_tenant_memberships')->where('id', $membership->getKey())->delete();
        }];

        yield 'the principal resolves as another' => [static function (ActivatableTenantMember $member, ActivatableTenantMembership $membership): void {
            $other = ActivatableTenantMember::query()->create(['email' => 'other@example.test', 'password' => 'unused']);

            ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $membership->tenant_id]);

            DB::table('activatable_tenant_memberships')->where('id', $membership->getKey())->update(['identity_id' => $other->getKey()]);
        }];

        yield 'the principal belongs to another identity' => [static function (ActivatableTenantMember $member, ActivatableTenantMembership $membership): void {
            $other = ActivatableTenantMember::query()->create(['email' => 'other@example.test', 'password' => 'unused']);

            DB::table('activatable_tenant_memberships')->where('id', $membership->getKey())->update(['identity_id' => $other->getKey()]);

            app()->instance(PrincipalResolver::class, new class implements PrincipalResolver {
                /**
                 * Resolve the hinted membership by its key, whoever owns it.
                 *
                 * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
                 * @param  mixed  $hint
                 * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
                 */
                #[\Override]
                public function resolve(Identity $identity, mixed $hint = null): ?Principal
                {
                    $principal = ActivatableTenantMembership::query()->find($hint);

                    return $principal instanceof Principal ? $principal : null;
                }
            });
        }];

        yield 'the row waits on nothing' => [static function (): void {
            DB::table('authentication_sessions')->update(['requires' => null]);
        }];
    }

    /**
     * A credential names nothing once the session's owner no longer loads
     * through the guard's provider, once the principal it records no longer
     * resolves or belongs to another identity, or once the pending row waits on
     * nothing: `pending()` answers `null`, and `satisfy()` and `choose()` fail
     * as `pending_invalid`.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\ActivatableTenantMember, \Tests\Integration\Fixtures\ActivatableTenantMembership): void  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesThatEndTheCredential')]
    public function testACredentialNamesNothingOnceItsSessionNoLongerHolds(\Closure $change): void
    {
        [$member, $membership] = $this->seedMember();

        [$credential, $pending] = $this->pendingSignIn('members', 'member@example.test');

        $change($member, $membership);

        self::assertNull($this->sessions('members')->pending($credential));
        $proof = self::adapterProof($member, 'members', $pending->id, Purpose::SIGN_IN);

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions('members')->satisfy($credential, $proof)->reason);
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions('members')->choose($credential, $membership)->reason);
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
    }

    /**
     * A pending session that records a principal names the tenant it records as
     * the one it is to be active in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionNamesTheTenantItRecords(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        [$credential] = $this->pendingSignIn('members', 'member@example.test');

        $found = $this->sessions('members')->pending($credential);

        self::assertNotNull($found);
        self::assertTrue($membership->is($found->principal));
        self::assertInstanceOf(ActivatableTenant::class, $found->tenant);
        self::assertTrue($tenant->is($found->tenant));
    }

    /**
     * A choice may name the tenant the principal is to be active in: with an
     * application tree that lets the principal act in a tenant below its own,
     * the session activates there, records it, and every request it
     * authenticates acts in it; with the defaults the same choice is refused as
     * `tenant_ineligible` and the session keeps waiting.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceMayNameATenantTheApplicationLetsThePrincipalActIn(): void
    {
        $this->factorRequired = false;

        [, $first] = $this->seedChooser();

        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);

        [$refusedCredential] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $refused = $this->sessions(self::CHOOSERS)->choose($refusedCredential, $first, TenantSelection::of($descendant->getKey()));

        self::assertSame(FailureReason::TENANT_INELIGIBLE, $refused->reason);
        self::assertNotNull($this->sessions(self::CHOOSERS)->pending($refusedCredential, PendingAction::CHOOSE_PRINCIPAL));

        $tree = (new DescendantTenants)->place($descendant->getKey(), $first->tenant_id);

        app()->instance(TenantAccess::class, $tree);
        app()->instance(TenantResolver::class, $tree);

        [$credential] = $this->pendingSignIn(self::CHOOSERS, 'chooser@example.test');

        $chosen = $this->sessions(self::CHOOSERS)->choose($credential, $first, TenantSelection::of($descendant->getKey()));

        self::assertTrue($chosen->isSignedIn());
        self::assertNotNull($chosen->session);
        self::assertTrue($first->is($chosen->session->principal));
        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), Session::query()->whereKey($chosen->session->record->getKey())->sole()->getTenantId());

        Route::middleware('auth:' . self::CHOOSERS)->get('/choosers/tenant', static fn (): array => ['tenant' => Auth::tenant()?->getTenantIdentifier()]);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $chosen->session->tokens->accessToken->reveal()])
            ->getJson('/choosers/tenant')
            ->assertOk()
            ->assertExactJson(['tenant' => $descendant->getKey()]);
    }

    /**
     * A pending session waits from its sign-in: a further factor proved the
     * second before it is refused as `proof_invalid`, and one proved in its
     * second activates it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionRefusesAProofFromBeforeItsSignIn(): void
    {
        $identity = $this->seedIdentity();

        [$credential, $pending] = $this->pendingSignIn();

        $early = self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN, at: $this->now->subSecond());

        self::assertSame(FailureReason::PROOF_INVALID, $this->sessions()->satisfy($credential, $early)->reason);
        self::assertTrue($this->sessions()->satisfy($credential, self::adapterProof($identity, 'api', $pending->id, Purpose::SIGN_IN, at: $this->now))->isSignedIn());
    }

    /**
     * A session that returned to pending waits from the return: a further
     * factor proved after its sign-in but before the return is refused as
     * `proof_invalid`, and one proved since activates it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnedSessionRefusesAProofFromBeforeItsReturn(): void
    {
        $this->factorRequired = false;

        [$member] = $this->seedMember();

        $signedIn = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($signedIn);

        $signedInAt = $this->now;

        $this->clockAt($this->now->addSeconds(5));

        $returned = $this->returnToPending($signedIn->tokens->refreshToken?->reveal());

        $early = self::adapterProof($member, 'members', $returned->pending?->id, Purpose::SIGN_IN, at: $signedInAt->addSeconds(2));

        self::assertSame(FailureReason::PROOF_INVALID, $this->sessions('members')->satisfy((string) $returned->credential?->reveal(), $early)->reason);

        $since = self::adapterProof($member, 'members', $returned->pending?->id, Purpose::SIGN_IN, at: $this->now);

        self::assertTrue($this->sessions('members')->satisfy((string) $returned->credential?->reveal(), $since)->isSignedIn());
    }

    /**
     * A session that returns to pending and activates again within one second
     * refuses every token issued before the return, and those its activation
     * issued, until that second has passed: a refresh then gives it a pair that
     * authenticates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnAndAnActivationWithinOneSecondReviveNoEarlierToken(): void
    {
        $this->factorRequired = false;

        [$member] = $this->seedMember();

        Route::middleware('auth:members')->get('/members/me', static fn (): array => ['ok' => true]);

        $signedIn = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($signedIn);

        $returned = $this->returnToPending($signedIn->tokens->refreshToken?->reveal());
        $active   = $this->sessions('members')->satisfy(
            (string) $returned->credential?->reveal(),
            self::adapterProof($member, 'members', $returned->pending?->id, Purpose::SIGN_IN),
        );

        self::assertTrue($active->isSignedIn());
        self::assertNotNull($active->session);
        self::assertSame($this->now->addSecond()->getTimestamp(), Session::query()->sole()->getSwitchedAt()?->getTimestamp());

        foreach ([$signedIn->tokens->accessToken->reveal(), $active->session->tokens->accessToken->reveal()] as $token) {
            Auth::forgetGuards();

            $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/members/me')->assertUnauthorized();
        }

        $this->clockAt($this->now->addSecond());

        $refreshed = $this->sessions('members')->refresh($active->session->tokens->refreshToken?->reveal())->session;

        self::assertNotNull($refreshed);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $refreshed->tokens->accessToken->reveal()])->getJson('/members/me')->assertOk();
    }

    /**
     * Configure the session guards and the guard over choosing members.
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
        $config->set('auth.providers.verifiable_choosers', ['driver' => 'model', 'model' => VerifiableChoosingMember::class]);
        $config->set('auth.guards.' . self::VERIFIED, [
            'driver'      => 'jwt',
            'provider'    => 'verifiable_choosers',
            'application' => ['methods' => ['password'], 'require_verified_identifier' => true],
        ]);
    }

    /**
     * Sign the identity with the email in on the guard, expecting a pending
     * session, and return its credential and the pending session.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Sessions\PendingSession}
     *
     * @throws \Throwable
     */
    private function pendingSignIn(string $guard = 'api', string $email = 'ada@example.test'): array
    {
        $result = $this->sessions($guard)->signIn('password', self::credentials($email));

        self::assertTrue($result->isPending(), 'Expected a pending session; got ' . self::describe($result));
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        return [$result->credential->reveal(), $result->pending];
    }

    /**
     * Refresh the session with the refresh token under a tenant policy that now
     * asks for a further factor, which returns it to pending, and bind a check
     * that meets that factor once the session holds one.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Throwable
     */
    private function returnToPending(#[\SensitiveParameter] string $refreshToken): RefreshResult
    {
        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', new Requirement(new RequirementPart))));
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $returned = $this->sessions('members')->refresh($refreshToken);

        self::assertTrue($returned->isPending());
        self::assertNotNull($returned->credential);

        return $returned;
    }

    /**
     * Persist a member with two memberships, each in an active tenant of its
     * own, so a sign-in that names no principal waits for a choice.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership, 2: \Tests\Integration\Fixtures\ChoosingMembership}
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
     * A result as its status and reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return string
     */
    private static function describe(SignInResult $result): string
    {
        return $result->status->value . ' ' . ($result->reason->value ?? '');
    }

    /**
     * Move the clocks to the time.
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
