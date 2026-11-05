<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Sessions\ProvenSessions;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Factors\FirstFactorMeetsRequirements;
use Tests\Fixtures\Sessions\InterruptingFactorPolicy;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of session establishment on its own: what it writes, returns
 * and schedules for an admitted sign-in, a required further factor and a
 * completion, and that it never binds the guard, which is the session service's
 * to do once it has returned.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionEstablishment::class)]
final class SessionEstablishmentTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var list<array<string, string>> The windows of the slots a sign-in took, as a limiter records them. */
    private const array WINDOWS = [['ip' => '1:60'], ['identifier' => '1:60']];

    /** @var ?\SineMacula\Laravel\Authentication\Guards\JwtGuard The guard the last establishment was built for. */
    private ?JwtGuard $establishing = null;

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
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
     * An admitted sign-in is written on a new session and reported, with
     * `SessionCreated` and then `SignedIn`, while the guard stays a guest: no
     * bind event fires and nothing is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionIsWrittenAndReportedWithoutBindingTheGuard(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        $this->recordEvents([SessionCreated::class, SignedIn::class, Login::class, Authenticated::class]);

        $result = self::outcome($this->establishment($guard)->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ));

        self::assertTrue($result->isSignedIn());
        self::assertSame(1, DB::table('authentication_sessions')->count());
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        EventContextAssertions::assertSession($result->session?->record, $this->recordedEvent(SignedIn::class)->context);
        EventContextAssertions::assertSession($result->session?->record, $this->recordedEvent(SessionCreated::class)->context);
        self::assertFalse($this->recordedEvent(SignedIn::class)->refresh);
        self::assertTrue($guard->guest());
    }

    /**
     * Rows of `[whether the identity-level factor policy asks for a further
     * factor, so the session is written pending]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideWrites(): iterable
    {
        yield 'active' => [false];
        yield 'pending' => [true];
    }

    /**
     * A session written after its identity was deactivated, past the sign-in's
     * admission, is checked once committed and reported by nothing: it is
     * revoked as `identity_deactivated`, and the call's check holds the refusal
     * the session service answers with.
     *
     * @param  bool  $pending
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideWrites')]
    public function testASessionWrittenAfterItsIdentityStoppedStandingIsNeverReported(bool $pending): void
    {
        $identity = $this->seedIdentity();
        $change   = static fn (): int => IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($change, $pending ? new Requirement(new RequirementPart) : new Requirement));

        $this->recordEvents([SessionCreated::class, SignedIn::class, SessionPending::class, SessionRevoked::class]);

        $establishing = $this->establishment($this->freshGuard());
        $recheck      = $this->recheck();

        $proof = SignInProof::unattested('password', CarbonImmutable::now());

        self::assertSame(!$pending, self::outcome($establishing->proceed($identity, self::selected($identity), 'email', $this->context(), $proof, $recheck))->isSignedIn());
        self::assertSame([], $this->recordedClasses());
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $recheck->refusal()?->reason);
        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A replacing sign-in whose identity stopped standing before its write
     * still reports the proven session it superseded, which stays revoked, but
     * nothing reports the new session, which the check revokes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplacementThatFailsItsCheckStillReportsTheSupersededSession(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            null,
            $this->context(),
            SignInProof::unattested('sso', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertNotNull($first);

        $change = static fn (): int => IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($change));

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        $recheck  = $this->recheck();
        $replaced = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context($first->tokens->refreshToken?->reveal()),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $recheck,
        ))->session;

        self::assertNotNull($replaced);
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::SUPERSEDED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $recheck->refusal()?->reason);
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertSame('identity_deactivated', DB::table('authentication_sessions')->where('id', $replaced->record->getKey())->value('revoked_reason'));
    }

    /**
     * Inside a caller's transaction the reports wait for its commit, and the
     * guard is still not bound in between.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportsWaitForTheCallersCommit(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue(self::outcome($this->establishment($guard)->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->isSignedIn());
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
    }

    /**
     * A client that proves it holds a session of the same identity and
     * principal gets a new session, and the proven one is revoked as
     * `superseded`. Once the caller's transaction commits, the revocation is
     * reported first, for the proven session with the method it records and the
     * sign-in's client, then `SessionCreated` and `SignedIn` for the new
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenSessionIsReplacedAndReportedInOrder(): void
    {
        $identity     = $this->seedIdentity();
        $guard        = $this->freshGuard();
        $establishing = $this->establishment($guard);
        $first        = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            null,
            $this->context(),
            SignInProof::unattested('sso', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertNotNull($first);

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $replaced = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context($first->tokens->refreshToken?->reveal()),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertNotNull($replaced);
        self::assertNotSame($first->record->getKey(), $replaced->record->getKey());
        self::assertSame(2, DB::table('authentication_sessions')->count());
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $replaced->record->getKey())->value('revoked_at'));
        self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(SessionRevoked::class);

        self::assertSame(RevocationReason::SUPERSEDED, $revoked->reason);
        self::assertSame(IdentifierCoercion::stringify($first->record->getKey()), $revoked->context->sessionId);
        self::assertSame('api', $revoked->context->guard);
        self::assertSame('sso', $revoked->context->method);
        EventContextAssertions::assertIdentity($identity, $revoked->context);
        EventContextAssertions::assertPrincipal($identity, $revoked->context);
        self::assertSame(self::CLIENT_IP, $revoked->context->client->ip);
        self::assertSame(IdentifierCoercion::stringify($replaced->record->getKey()), $this->recordedEvent(SessionCreated::class)->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($replaced->record->getKey()), $this->recordedEvent(SignedIn::class)->context->sessionId);
        self::assertSame('password', $this->recordedEvent(SignedIn::class)->context->method);
        self::assertTrue($guard->guest());
    }

    /**
     * A replacement rolled back by its caller reports nothing and leaves the
     * proven session live, with no new session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARolledBackReplacementReportsNothing(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertNotNull($first);

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertTrue(self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context($first->tokens->refreshToken?->reveal()),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->isSignedIn());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, DB::table('authentication_sessions')->count());
        self::assertNull(DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_at'));
    }

    /**
     * A replacement whose new session a model event cancels reports nothing,
     * and its exception reaches the caller with the proven session still live
     * at its digest and no new session written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACanceledReplacementReportsNothing(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertNotNull($first);

        $before = (array) DB::table('authentication_sessions')->where('id', $first->record->getKey())->first();

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        Session::creating(static fn (): bool => false);

        try {
            self::outcome($establishing->proceed(
                $identity,
                self::selected($identity),
                'email',
                $this->context($first->tokens->refreshToken?->reveal()),
                SignInProof::unattested('password', CarbonImmutable::now()),
                $this->recheck(),
            ));
            self::fail('Expected the cancelled replacement to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(Session::class . ' was not saved: a model event cancelled the new session, so the sign-in wrote nothing.', $exception->getMessage());
        }

        self::assertSame([], $this->recordedClasses());
        self::assertSame($before, (array) DB::table('authentication_sessions')->where('id', $first->record->getKey())->first());
        self::assertSame(1, DB::table('authentication_sessions')->count());
    }

    /**
     * A proof whose session changes before it can be replaced (here a refresh
     * rotates it while the factor policy is asked) is dropped: the sign-in is
     * reconsidered without it, the policy asked again with no proven session,
     * and a new session starts while the refreshed one stays live and
     * unreported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofThatMissesTheSwapIsReconsideredWithoutIt(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertNotNull($first);

        /** @var \ArrayObject<int, mixed> $asked */
        $asked = new \ArrayObject;

        app()->instance(AdditionalFactorPolicy::class, new readonly class ($asked, IdentifierCoercion::stringify($first->record->getKey())) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, mixed>  $asked
             * @param  ?string  $record
             */
            public function __construct(

                /** The proven session of every context asked about, in order. */
                private \ArrayObject $asked,

                /** The session a refresh rotates the first time the policy is asked. */
                private ?string $record,
            ) {}

            /**
             * Record the proven session, rotating it the first time.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                if ($this->asked->count() === 0) {
                    DB::table('authentication_sessions')->where('id', $this->record)->update(['refresh_key' => str_repeat('a', 64)]);
                }

                $this->asked->append($context->provenSession?->getSessionIdentifier());

                return new Requirement;
            }
        });

        $this->recordEvents([SessionRevoked::class, SessionCreated::class, SignedIn::class]);

        $session = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context($first->tokens->refreshToken?->reveal()),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertNotNull($session);
        self::assertSame([$first->record->getKey(), null], $asked->getArrayCopy());
        self::assertSame(2, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $this->recordedEvent(SignedIn::class)->context->sessionId);
    }

    /**
     * A listener on the replaced session's revocation that throws stops the
     * reports after it, and its exception reaches the caller, while the
     * committed writes stand: the proven session revoked, the new one live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationListenerThatThrowsStopsTheLaterReports(): void
    {
        $identity     = $this->seedIdentity();
        $establishing = $this->establishment($this->freshGuard());
        $first        = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->session;

        self::assertNotNull($first);

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        Event::listen(SessionRevoked::class, static function (): void {
            throw new \RuntimeException('revocation listener failed');
        });

        try {
            self::outcome($establishing->proceed(
                $identity,
                self::selected($identity),
                'email',
                $this->context($first->tokens->refreshToken?->reveal()),
                SignInProof::unattested('password', CarbonImmutable::now()),
                $this->recheck(),
            ));
            self::fail('Expected the revocation listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('revocation listener failed', $exception->getMessage());
        }

        self::assertSame([], $this->recordedClasses());
        self::assertSame('superseded', DB::table('authentication_sessions')->where('id', $first->record->getKey())->value('revoked_reason'));
        self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame(2, DB::table('authentication_sessions')->count());
    }

    /**
     * When the additional-factor policy asks for a further factor the default
     * check never finds met, the sign-in is written as a pending session
     * waiting on it, naming the requirement and the first factor it recorded,
     * carrying the slots it took and holding no token, reported by
     * `SessionPending` once committed; no session is created or signed in and
     * the guard is not bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequiredFactorHoldsTheSignIn(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        self::requireAFurtherFactor(true);

        $this->recordEvents([SessionPending::class, SessionCreated::class, SignedIn::class]);

        $result = self::outcome($this->establishment($guard)->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
            self::WINDOWS,
        ));

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending);
        self::assertSame([PendingRequirement::MFA], $result->pending->requires);
        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION], $result->pending->requirement->kinds());
        self::assertSame(SessionProof::query()->sole()->getKey(), $result->pending->firstFactor->id);
        self::assertSame(ProofKind::FIRST_FACTOR, $result->pending->firstFactor->kind);
        self::assertSame($identity, $result->pending->principal);
        self::assertSame(CarbonImmutable::now()->addMinutes(5)->getTimestamp(), $result->pending->expiresAt->getTimestamp());
        self::assertStringStartsWith(IdentifierCoercion::stringify($result->pending->id) . '.', (string) $result->credential?->reveal());

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::PENDING, $row->getStatus());
        self::assertNull($row->getRefreshKey());
        self::assertSame(self::WINDOWS, $row->attempt_windows);
        self::assertSame([SessionPending::class], $this->recordedClasses());
        self::assertSame(['mfa'], $this->recordedEvent(SessionPending::class)->requires);
        self::assertTrue($guard->guest());
    }

    /**
     * A sign-in with principals to choose from is written as a pending session
     * waiting on the choice, after the further factor when one is required,
     * recording no principal and listing none until the factor is met: the
     * holder of the first factor alone never sees the identity's principals.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceHoldsTheSignInAfterTheFactor(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        self::requireAFurtherFactor(true);

        $result = self::outcome($this->establishment($this->freshGuard())->proceed(
            $identity,
            [null, [$identity, $other]],
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ));

        self::assertNotNull($result->pending);
        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], $result->pending->requires);
        self::assertNull($result->pending->principal);
        self::assertSame([], $result->pending->principals);
        self::assertNull(Session::query()->sole()->principal_id);
    }

    /**
     * A sign-in whose only outstanding requirement is the choice lists the
     * principals to choose from on the pending session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceAloneListsThePrincipals(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');

        self::requireAFurtherFactor(false);

        $result = self::outcome($this->establishment($this->freshGuard())->proceed(
            $identity,
            [null, [$identity, $other]],
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ));

        self::assertNotNull($result->pending);
        self::assertSame([PendingRequirement::PRINCIPAL], $result->pending->requires);
        self::assertSame([$identity, $other], $result->pending->principals);
    }

    /**
     * A sign-in whose deadline is this second or earlier is refused as
     * `session_expired` with the identity, before its principals are read, the
     * factor policy is asked, or anything is written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInPastItsDeadlineIsRefusedBeforeAnything(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        self::requireAFurtherFactor(true);

        $this->recordEvents([SessionPending::class, SessionCreated::class, SignedIn::class]);

        foreach ([CarbonImmutable::now(), CarbonImmutable::now()->subMinute()] as $deadline) {

            $refused = $this->establishment($guard)->select($identity, null, $this->context(notAfter: $deadline));

            self::assertInstanceOf(Refused::class, $refused);
            self::assertSame(FailureReason::SESSION_EXPIRED, $refused->reason);
            self::assertSame($identity, $refused->identity);
        }

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A deadline that passes between the selection and the session (a slow
     * principal lookup or password rehash, say) refuses the sign-in as
     * `session_expired` with the identity and principal, whether the session
     * would start active or pending, before the proof is checked, the factor
     * policy asked, or anything written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeadlinePassedSinceTheSelectionIsRefusedBeforeAnything(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();
        $deadline = CarbonImmutable::now()->addSecond();

        $this->recordEvents([SessionPending::class, SessionCreated::class, SignedIn::class]);

        foreach ([false, true] as $factor) {

            self::requireAFurtherFactor($factor);

            CarbonImmutable::setTestNow($deadline->subSecond());

            $selection = $this->establishment($guard)->select($identity, null, $this->context(notAfter: $deadline));

            self::assertIsArray($selection);

            CarbonImmutable::setTestNow($deadline);

            $proof   = SignInProof::unattested('password', CarbonImmutable::now());
            $refused = $this->establishment($guard)->proceed($identity, $selection, 'email', $this->context(notAfter: $deadline), $proof, $this->recheck());

            self::assertInstanceOf(Refused::class, $refused);
            self::assertSame(FailureReason::SESSION_EXPIRED, $refused->reason);
            self::assertSame($identity, $refused->identity);
            self::assertSame($selection[0], $refused->principal);
        }

        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A sign-in naming a tenant its principal may not act in is refused as
     * `tenant_ineligible`, with the principal and the session the client proved
     * it holds, before the tenant's policy is asked or anything is written: the
     * proven session stays live and nothing is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantThePrincipalMayNotActInIsRefusedBeforeAnyWrite(): void
    {
        [$member, $membership] = $this->seedMember();

        self::requireAFurtherFactor(false);

        $policy       = $this->bindTenantPolicy(new TenantRequirement('v1'));
        $establishing = $this->establishment($this->freshGuard('members'));
        $proof        = SignInProof::unattested('password', CarbonImmutable::now());
        $first        = self::outcome($establishing->proceed($member, [$membership, []], 'email', $this->context(), $proof, $this->recheck()))->session;

        self::assertNotNull($first);

        $elsewhere = ActivatableTenant::query()->create(['name' => 'Elsewhere', 'is_active' => true]);
        $asked     = count($policy->asked);
        $context   = SignInContext::fromRequest(app('request'), refreshToken: $first->tokens->refreshToken?->reveal(), tenant: TenantSelection::of($elsewhere->getKey()));

        $this->recordEvents([SessionRevoked::class, SessionPending::class, SessionCreated::class, SignedIn::class]);

        $refused = $establishing->proceed($member, [$membership, []], 'email', $context, $proof, $this->recheck());

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::TENANT_INELIGIBLE, $refused->reason);
        self::assertSame($member, $refused->identity);
        self::assertTrue($membership->is($refused->principal));
        self::assertNull($refused->tenant);
        self::assertInstanceOf(Session::class, $refused->session);
        self::assertSame($first->record->getKey(), $refused->session->getKey());
        self::assertCount($asked, $policy->asked);
        self::assertSame(1, DB::table('authentication_sessions')->count());
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A sign-in whose deadline is ahead starts a session capped at it: its
     * absolute deadline is the deadline, and its idle one no later.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInsDeadlineCapsItsSession(): void
    {
        $identity = $this->seedIdentity();
        $deadline = CarbonImmutable::now()->addSecond();

        $establishing = $this->establishment($this->freshGuard());
        $record       = self::outcome($establishing->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(notAfter: $deadline),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ))->session?->record;

        self::assertNotNull($record);
        self::assertSame($deadline->getTimestamp(), $record->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($deadline->getTimestamp(), $record->getIdleExpiresAt()?->getTimestamp());
    }

    /**
     * A selected principal whose tenant requires a connection the sign-in did
     * not come through is refused as `sso_required`, with the principal and
     * tenant it was refused in, before anything is written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantRequiringAConnectionRefusesTheSignInBeforeAnyWrite(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $policy = $this->bindTenantPolicy(new TenantRequirement('v1', connections: ['conn-a']));

        $this->recordEvents([SessionPending::class, SessionCreated::class, SignedIn::class]);

        $refused = $this->establishment($this->freshGuard('members'))->proceed(
            $member,
            [$membership, []],
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        );

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::SSO_REQUIRED, $refused->reason);
        self::assertTrue($membership->is($refused->principal));
        self::assertTrue($tenant->is($refused->tenant));
        self::assertSame(0, DB::table('authentication_sessions')->count());
        self::assertSame([], $this->recordedClasses());
        self::assertCount(1, $policy->asked);
        self::assertNull($policy->asked[0]->session);
    }

    /**
     * A selected principal whose tenant requires a further factor the sign-in
     * did not prove holds the sign-in pending on `mfa`, its principal and
     * tenant recorded with the version the policy answered, though the
     * identity's own policy asks for none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantRequiringAFactorHoldsTheSignInPendingOnIt(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        self::requireAFurtherFactor(false);

        $this->bindTenantPolicy(new TenantRequirement('v1', new Requirement(new RequirementPart)));

        $result = self::outcome($this->establishment($this->freshGuard('members'))->proceed(
            $member,
            [$membership, []],
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ));

        self::assertTrue($result->isPending());
        self::assertSame([PendingRequirement::MFA], $result->pending?->requires);

        $row = Session::query()->sole();

        self::assertSame(SessionStatus::PENDING, $row->getStatus());
        self::assertSame('v1', $row->getTenantPolicyVersion());
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), $row->principal_id);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $row->getTenantId());
    }

    /**
     * A selected principal whose tenant's policy the sign-in meets starts the
     * session active, recording the version the policy answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMetTenantPolicyRecordsItsVersionOnTheActiveSession(): void
    {
        [$member, $membership] = $this->seedMember();

        self::requireAFurtherFactor(false);

        $this->bindTenantPolicy(new TenantRequirement('v3'));

        $result = self::outcome($this->establishment($this->freshGuard('members'))->proceed(
            $member,
            [$membership, []],
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ));

        self::assertTrue($result->isSignedIn());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
        self::assertSame('v3', Session::query()->sole()->getTenantPolicyVersion());
    }

    /**
     * A requirement the bound check finds the first factor alone meets (an
     * assurance level the password already reaches, say) starts the session
     * active at sign-in, judged on the sign-in's own proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequirementTheFirstFactorMeetsStartsTheSessionActive(): void
    {
        $identity = $this->seedIdentity();

        self::requireAFurtherFactor(true);

        app()->instance(RequirementCheck::class, new FirstFactorMeetsRequirements);

        $result = self::outcome($this->establishment($this->freshGuard())->proceed(
            $identity,
            self::selected($identity),
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ));

        self::assertTrue($result->isSignedIn());
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
    }

    /**
     * A sign-in short of both the identity's requirement and its tenant's waits
     * on the strictest of the two: every part either asks for.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInNamesTheStrictestOfTheIdentitysAndTheTenantsRequirements(): void
    {
        [$member, $membership] = $this->seedMember();

        self::requireAFurtherFactor(true);

        $this->bindTenantPolicy(new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart(600))));

        $result = self::outcome($this->establishment($this->freshGuard('members'))->proceed(
            $member,
            [$membership, []],
            'email',
            $this->context(),
            SignInProof::unattested('password', CarbonImmutable::now()),
            $this->recheck(),
        ));

        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::MULTIFACTOR], $result->pending?->requirement->kinds());
        self::assertSame(600, $result->pending->requirement->multifactor?->maxAgeSeconds);
    }

    /**
     * Register the session guards.
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
     * The establishment of the guard's sessions, built from the collaborators
     * the session service builds it with.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionEstablishment
     */
    private function establishment(JwtGuard $guard): SessionEstablishment
    {
        $connections = app(ConnectionResolverInterface::class);

        $this->establishing = $guard;

        return new SessionEstablishment(
            $guard->context(),
            new SessionWriter($guard->getName(), $guard->tokens(), $connections),
            new ProvenSessions($guard->tokens()),
            new PendingEvaluation($guard->context(), app()),
            new AfterCommit(static fn (): mixed => app('db.transactions')),
            app(),
        );
    }

    /**
     * The check of a sign-in through the guard the last establishment was built
     * for, made for the request's client and begun now, as the session service
     * makes it.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck
     */
    private function recheck(): AdmissionRecheck
    {
        $guard = $this->establishing;

        self::assertNotNull($guard);

        return new AdmissionRecheck(
            $guard->context(),
            $guard,
            new RevocationWriter(app(ConnectionResolverInterface::class), static fn (): mixed => app('db.transactions')),
            new AfterCommit(static fn (): mixed => app('db.transactions')),
            $guard->context()->client(),
            CarbonImmutable::now()->startOfSecond(),
        );
    }

    /**
     * The context of a sign-in from the request, with the refresh token the
     * client presents, if any, and the deadline the session may last until, if
     * any.
     *
     * @param  ?string  $refreshToken
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    private function context(#[\SensitiveParameter] ?string $refreshToken = null, ?CarbonInterface $notAfter = null): SignInContext
    {
        return SignInContext::fromRequest(app('request'), refreshToken: $refreshToken)->withNotAfter($notAfter);
    }

    /**
     * The sign-in result establishment answered, asserting it was not refused.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult  $outcome
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private static function outcome(Refused|SignInResult $outcome): SignInResult
    {
        self::assertInstanceOf(SignInResult::class, $outcome);

        return $outcome;
    }

    /**
     * The identity selected as its own principal, with none to choose from.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return array{0: \Tests\Integration\Fixtures\IntegrationIdentity, 1: list<\SineMacula\Laravel\Authentication\Contracts\Principal>}
     */
    private static function selected(IntegrationIdentity $identity): array
    {
        return [$identity, []];
    }

    /**
     * Bind a tenant authentication policy that answers every tenant with the
     * requirement, and return it.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @return \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy
     */
    private function bindTenantPolicy(TenantRequirement $requirement): ScriptedTenantAuthenticationPolicy
    {
        $policy = new ScriptedTenantAuthenticationPolicy($requirement);

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        return $policy;
    }

    /**
     * Bind an additional-factor policy that always gives the answer.
     *
     * @param  bool  $required
     * @return void
     */
    private static function requireAFurtherFactor(bool $required): void
    {
        app()->instance(AdditionalFactorPolicy::class, new readonly class ($required) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  bool  $required
             */
            public function __construct(

                /** The answer to give. */
                private bool $required,
            ) {}

            /**
             * Give the answer.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return $this->required ? new Requirement(new RequirementPart) : new Requirement;
            }
        });
    }
}
