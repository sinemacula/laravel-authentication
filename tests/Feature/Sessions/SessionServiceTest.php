<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionPreconditions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRecheckedMembers;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Sessions\InterruptingFactorPolicy;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\Fixtures\Sessions\RefusalIgnoringSignIn;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\NormalizedEmailIdentity;
use Tests\TestCase;

/**
 * Feature tests for the session service's sign-in pipeline: what `signIn()` and
 * `start()` check, in which order, what each failure reports, what a success
 * writes, binds and dispatches, and what the sign-in policies are asked.
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
#[CoversClass(SignInResult::class)]
final class SessionServiceTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRecheckedMembers, InteractsWithSessions;

    /** @var string Cookie application over identities. */
    private const string BROWSER = 'browser';

    /** @var string Cookie application over members with no default principal. */
    private const string BROWSER_CHOOSERS = 'browser_choosers';

    /** @var string The test request's own origin. */
    private const string OWN_ORIGIN = 'http://localhost';

    /** @var string An origin the cookie applications allow besides their own. */
    private const string ALLOWED_ORIGIN = 'https://app.example.test';

    /** @var array<string, string> The headers a page of the cookie applications' own site sends. */
    private const array SAME_SITE = ['Origin' => self::OWN_ORIGIN, 'X-Requested-With' => 'fetch'];

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

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
        $this->dropRecheckedTables();
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A password sign-in starts a new session: the result carries the identity,
     * principal, session, method and first pair; the session records who, as
     * whom, through which guard and method, from which client, the sign-in as
     * its last use, the digest of the refresh token's rotation id, and the
     * guard's deadlines; and the guard is bound to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInStartsASessionOnANewSession(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        $result = self::sessionsOf($guard)->signIn('password', self::credentials(), SignInContext::fromRequest(app('request'), 'Work laptop', 'macOS'));

        self::assertTrue($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertSame(SignInStatus::SIGNED_IN, $result->status);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);

        $session = $result->session;

        self::assertNotNull($session);
        self::assertSameModel($identity, $session->identity);
        self::assertSame($session->identity, $session->principal);
        self::assertSame('password', $session->method);

        $record = Session::query()->whereKey($session->record->getKey())->firstOrFail();
        $claims = Auth::manager()->jwt('api')->parse($session->tokens->refreshToken?->reveal());

        self::assertNotNull($claims);
        self::assertSame($record->getKey(), $claims['sid']);
        self::assertSame(IntegrationIdentity::class, $record->authenticatable_type);
        self::assertSame((string) $identity->id, $record->authenticatable_id);
        self::assertSame(IntegrationIdentity::class, $record->principal_type);
        self::assertSame((string) $identity->id, $record->principal_id);
        self::assertSame('api', $record->getGuard());
        self::assertSame('password', $record->getSignInMethod());
        self::assertSame('Work laptop', $record->client_name);
        self::assertSame('macOS', $record->platform);
        self::assertSame(self::CLIENT_IP, $record->created_ip);
        self::assertSame(self::CLIENT_AGENT, $record->created_user_agent);
        self::assertSame(self::CLIENT_IP, $record->last_used_ip);
        self::assertSame(self::CLIENT_AGENT, $record->last_used_user_agent);
        self::assertSame($this->now->getTimestamp(), $record->getLastUsedAt()?->getTimestamp());
        self::assertIsString($claims['jti']);
        self::assertTrue(RefreshTokenHasher::verify($claims['jti'], (string) $record->getRefreshKey()));
        self::assertNull($record->getPreviousRefreshKey());
        self::assertNull($record->getRefreshRotatedAt());
        self::assertSame($this->now->addDays(30)->getTimestamp(), $record->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addDays(180)->getTimestamp(), $record->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertNull($record->getRevokedAt());

        self::assertSame($session->identity, $guard->user());
        self::assertSame($session->principal, $guard->principal());
        self::assertSame($session->record, $guard->session());
    }

    /**
     * A successful sign-in announces itself in a fixed order: `Attempting`,
     * then `SessionCreated` and `SignedIn`, reported before the bind, then the
     * bind events, each lifecycle event carrying the sign-in's context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInDispatchesSessionCreatedAndSignedInThenTheBindEvents(): void
    {
        $this->seedIdentity();

        $this->recordEvents([
            Attempting::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            PrincipalAssigned::class,
            SessionAuthenticated::class,
            SessionCreated::class,
            SignedIn::class,
            Failed::class,
            AuthenticationFailed::class,
        ]);

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertSame(
            [
                Attempting::class,
                SessionCreated::class,
                SignedIn::class,
                Validated::class,
                Login::class,
                Authenticated::class,
                PrincipalAssigned::class,
                SessionAuthenticated::class,
            ],
            $this->recordedClasses(),
        );

        $session  = $result->session;
        $created  = $this->recordedEvent(SessionCreated::class);
        $signedIn = $this->recordedEvent(SignedIn::class);

        self::assertNotNull($session);

        foreach ([$created, $signedIn] as $event) {
            self::assertSame('api', $event->context->guard);
            EventContextAssertions::assertIdentity($session->identity, $event->context);
            EventContextAssertions::assertPrincipal($session->principal, $event->context);
            EventContextAssertions::assertTenant(null, $event->context);
            EventContextAssertions::assertSession($session->record, $event->context);
            self::assertSame('password', $event->context->method);
            self::assertSame(self::CLIENT_IP, $event->context->client->ip);
            self::assertSame(self::CLIENT_AGENT, $event->context->client->userAgent);
        }

        self::assertFalse($signedIn->refresh);
    }

    /**
     * The events never see the input: `Attempting` and `Failed` carry only the
     * identifier the method names, and `AuthenticationFailed` no secret at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEventsCarryOnlyTheIdentifierNeverTheInput(): void
    {
        $this->seedIdentity();

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class]);

        $input = ['email' => 'ada@example.test', 'password' => 'not-the-password', 'otp' => '123456', 'remember' => 'yes'];

        $result = $this->sessions()->signIn('password', $input, self::requestContext());

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $result->reason);
        self::assertSame(['email' => 'ada@example.test'], $this->recordedEvent(Attempting::class)->credentials);
        self::assertFalse($this->recordedEvent(Attempting::class)->remember);
        self::assertSame(['email' => 'ada@example.test'], $this->recordedEvent(Failed::class)->credentials);
        self::assertNull($this->recordedEvent(Failed::class)->user);

        $failed = serialize($this->recordedEvent(AuthenticationFailed::class));

        self::assertStringNotContainsString('not-the-password', $failed);
        self::assertStringNotContainsString('123456', $failed);
    }

    /**
     * The credential timebox is cut short only for a sign-in whose method
     * verified the input and whose identity was admitted: a wrong password
     * waits it out. What follows the identity's admission (here a required
     * factor, which leaves the session pending) runs after the timebox, once
     * the input is known to be right.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTimeboxIsCutShortOnlyForAnAdmittedSignIn(): void
    {
        $this->seedIdentity();

        /** @var \ArrayObject<int, bool> $early */
        $early = new \ArrayObject;

        $timebox = \Mockery::mock(Timebox::class);
        $timebox->shouldReceive('dontReturnEarly')->andReturnSelf();
        $timebox->shouldReceive('call')->andReturnUsing(static function (callable $callback) use ($early): mixed {
            $spy = new class extends Timebox {
                /** @var bool Whether returnEarly() was called. */
                public bool $early = false;

                /**
                 * Record the early return without sleeping.
                 *
                 * @return self
                 */
                #[\Override]
                public function returnEarly(): self
                {
                    $this->early = true;

                    return parent::returnEarly();
                }
            };

            $result = $callback($spy);

            $early->append($spy->early);

            return $result;
        });

        app()->instance(Timebox::class, $timebox);

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext())->isFailed());

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isPending());
        self::assertSame([true, false, true], $early->getArrayCopy());
    }

    /**
     * An unknown sign-in method is a misconfiguration: it throws before
     * anything is dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownMethodThrows(): void
    {
        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class]);

        try {
            $this->sessions()->signIn('carrier-pigeon', [], self::requestContext());
            self::fail('Expected an unknown method to throw.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Sign-in method [carrier-pigeon] is not registered.', $exception->getMessage());
        }

        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A method the guard does not allow fails before anything is counted or
     * looked up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodTheGuardDoesNotAllowFailsBeforeAnythingIsCounted(): void
    {
        $this->seedIdentity();

        $policy = $this->policy();
        $policy->shouldReceive('allowsMethod')->once()->with('api', 'password')->andReturnFalse();

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldNotReceive('acquire');

        $this->assertSignInFails(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->signIn('password', self::credentials(), self::requestContext()));
    }

    /**
     * A failed sign-in names the challenge its input answered once the guard
     * allows the method; a method it does not allow fails with none, since
     * nothing was checked, as a reauthentication does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedSignInNamesItsChallengeOnlyOnceTheMethodIsAllowed(): void
    {
        $this->registerTrustedMethod(FailureReason::INVALID_CREDENTIALS);

        $policy = $this->policy();
        $policy->shouldReceive('allowsMethod')->once()->with('api', 'trusted')->andReturnTrue();
        $policy->shouldReceive('allowsMethod')->once()->with('api', 'trusted')->andReturnFalse();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('trusted', ['challenge' => 'challenge-1'], self::requestContext())->reason);
        self::assertSame('challenge-1', $this->recordedEvent(AuthenticationFailed::class)->challengeId);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->signIn('trusted', ['challenge' => 'challenge-1'], self::requestContext())->reason);
        self::assertNull($this->recordedEvent(AuthenticationFailed::class)->challengeId);
    }

    /**
     * An attempt over its limit fails with the wait, without checking the
     * input; one under it takes a slot for the identifier as given, its type
     * and the client's IP address, then one on the account its password is
     * checked against, which a wrong password keeps; a success gives both back
     * once its session started.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAttemptLimitsAreReservedAndGivenBackOnlyOnSuccess(): void
    {
        $identity = $this->seedIdentity();

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject> $subjects */
        $subjects = new \ArrayObject;

        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation> $released */
        $released = new \ArrayObject;

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->andReturnUsing(static function (AttemptSubject $subject) use ($subjects): AttemptReservation {
            $subjects->append($subject);

            return new AttemptReservation($subject, count($subjects) === 1 ? 42 : null);
        });
        $limiter->shouldReceive('release')->andReturnUsing(static function (AttemptReservation $reservation) use ($released): void {
            $released->append($reservation);
        });

        $limited = $this->sessions()->signIn('password', ['email' => ' ADA@example.test ', 'password' => self::PASSWORD], self::requestContext());

        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(42, $limited->retryAfter);

        $wrong = $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext());

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $wrong->reason);
        self::assertCount(0, $released);

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
        self::assertCount(2, $released);

        [$limitedSubject, , $wrongAccount, $successSubject, $successAccount] = $subjects->getArrayCopy();
        [$release, $accountRelease]                                          = $released->getArrayCopy();

        self::assertSame($successAccount, $accountRelease->subject);
        self::assertSame($successSubject, $release->subject);
        self::assertSame(AccountAttempts::account($identity), $wrongAccount->account);
        self::assertNull($wrongAccount->identifier);
        self::assertNull($wrongAccount->ip);
        self::assertSame('api', $limitedSubject->guard);
        self::assertSame(AttemptFlow::SIGN_IN, $limitedSubject->flow);
        self::assertSame(' ADA@example.test ', $limitedSubject->identifier);
        self::assertSame('email', $limitedSubject->identifierType);
        self::assertSame(self::CLIENT_IP, $limitedSubject->ip);
        self::assertSame(1, Session::query()->count());
    }

    /**
     * A wrong password, an unknown identifier, and an inactive identity each
     * fail with their reason, start nothing, and bind nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRejectedCredentialsAndInactiveIdentitiesFail(): void
    {
        $this->seedIdentity();
        $this->seedIdentity('inactive@example.test', false);

        $this->assertSignInFails(
            FailureReason::INVALID_CREDENTIALS,
            $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext()),
        );
        $this->assertSignInFails(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', self::credentials('nobody@example.test'), self::requestContext()));
        $this->assertSignInFails(FailureReason::IDENTITY_INACTIVE, $this->sessions()->signIn('password', self::credentials('inactive@example.test'), self::requestContext()));
    }

    /**
     * A 3D sign-in acts as the identity's default membership, or as the
     * membership the context pins once it is proven to be the identity's own;
     * one of another member fails as a mismatch, and a member with no
     * membership as unresolved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPrincipalsAreResolvedOrPinnedAndProven(): void
    {
        [, $membership, $tenant] = $this->seedMember();
        [, $foreign]             = $this->seedMember('other@example.test', $tenant);

        $default = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertSameModel($membership, self::sessionOf($default)->principal);

        $context = new SignInContext(new ClientContext(null, null), principal: $membership);
        $pinned  = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context);

        $pinnedSession = self::sessionOf($pinned);

        self::assertSameModel($membership, $pinnedSession->principal);
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), Session::query()->whereKey($pinnedSession->record->getKey())->firstOrFail()->principal_id);

        $this->recordEvents([AuthenticationFailed::class]);

        $mismatch = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), new SignInContext(new ClientContext(null, null), principal: $foreign));

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $mismatch->reason);
        EventContextAssertions::assertPrincipal(null, $this->recordedEvent(AuthenticationFailed::class)->context);

        $membership->delete();
        $foreign->delete();

        self::assertSame(
            FailureReason::PRINCIPAL_UNRESOLVED,
            $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->reason,
        );
    }

    /**
     * A member whose only membership acts within an inactive tenant has no
     * principal left once its password is verified: the sign-in fails with the
     * reason that membership was left out for, naming the member and no
     * principal, since none was selected.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalInAnInactiveTenantFails(): void
    {
        $tenant = ActivatableTenant::query()->create(['name' => 'Closed', 'is_active' => false]);

        [$member] = $this->seedMember(tenant: $tenant);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->assertSignInFails(FailureReason::TENANT_INACTIVE, $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext()));
        EventContextAssertions::assertIdentity($member, $this->recordedEvent(AuthenticationFailed::class)->context);
        EventContextAssertions::assertPrincipal(null, $this->recordedEvent(AuthenticationFailed::class)->context);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * `ApplicationAccess` decides whether the principal may use the
     * application: refused for the member's only principal, none is left, so
     * the sign-in fails as `principal_ineligible` once the password is
     * verified, naming the member and no principal or tenant, since none was
     * selected.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheApplicationAccessRefusalFailsTheSignIn(): void
    {
        [$member, $membership] = $this->seedMember();

        $access = $this->bindMock(ApplicationAccess::class);
        $access->shouldReceive('mayUse')
            ->once()
            ->with('members', \Mockery::on(static fn (Principal $principal): bool => $principal->getPrincipalIdentifier() === $membership->getKey()))
            ->andReturnFalse();

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        $this->assertSignInFails(
            FailureReason::PRINCIPAL_INELIGIBLE,
            $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext()),
        );

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        EventContextAssertions::assertIdentity($member, $failed->context);
        EventContextAssertions::assertPrincipal(null, $failed->context);
        EventContextAssertions::assertTenant(null, $failed->context);
        self::assertSame('password', $failed->context->method);
        self::assertSame('member@example.test', $failed->identifier);
        self::assertSame($member->getKey(), $this->recordedEvent(Failed::class)->user?->getAuthIdentifier());
    }

    /**
     * An account with no attempts left is refused without its password being
     * checked: the client is answered `invalid_credentials` with no wait, as
     * for a wrong password, while `AuthenticationFailed` reports the account's
     * own limit and its wait, with no identity, since none was verified.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusalByTheAccountsLimitIsReportedOnlyToListeners(): void
    {
        $this->seedIdentity();

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->twice()->andReturnUsing(
            static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, $subject->account === null ? null : 90),
        );
        $limiter->shouldReceive('release')->never();

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        $this->assertSignInFails(FailureReason::INVALID_CREDENTIALS, $result);
        self::assertNull($result->retryAfter);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $failed->reason);
        self::assertSame(90, $failed->retryAfter);
        EventContextAssertions::assertIdentity(null, $failed->context);
        self::assertSame('ada@example.test', $failed->identifier);
        self::assertNull($this->recordedEvent(Failed::class)->user);
    }

    /**
     * A method that checks a secret although the account refused it the attempt
     * is not trusted with the identity it returns: the sign-in fails as refused
     * by the account's limit, starts no session, writes nothing, and gives no
     * slot back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodThatIgnoresTheAccountsRefusalSignsNobodyIn(): void
    {
        $this->seedIdentity();

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->twice()->andReturnUsing(
            static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, $subject->account === null ? null : 90),
        );
        $limiter->shouldReceive('release')->never();

        $manager = app(SignInMethodManager::class);

        $manager->forgetDrivers();
        $manager->extend('trusted', fn (): SignInMethod => new RefusalIgnoringSignIn);

        $this->recordEvents([AuthenticationFailed::class, SignedIn::class, SessionPending::class]);

        $result = $this->sessions()->signIn('trusted', self::credentials(), self::requestContext());

        $this->assertSignInFails(FailureReason::INVALID_CREDENTIALS, $result);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(90, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * The additional-factor policy is asked about every admitted sign-in, about
     * the identity alone (no principal or tenant), with the client's
     * description and no proven session; a sign-in it asks a factor of issues
     * no token: its session is pending, waiting on `mfa`, for the identity and
     * its principal, which does not fail the sign-in and keeps every slot the
     * sign-in took, the account's included, recording their windows on the
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorPolicyIsAskedAndARequiredFactorStartsNoSession(): void
    {
        $identity = $this->seedIdentity();
        $asked    = null;

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->once()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): Requirement {
            $asked = $context;

            return new Requirement(new RequirementPart);
        });

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->andReturnUsing(static function (AttemptSubject $subject): AttemptReservation {
            $slot = $subject->account === null ? 'sign-in' : 'account';

            return new AttemptReservation($subject, null, [$slot => '2026-04-06 12:05:00']);
        });
        $limiter->shouldReceive('release')->never();

        $this->recordEvents([Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class]);

        $guard   = $this->freshGuard();
        $context = SignInContext::fromRequest(app('request'), 'Phone', 'iOS');
        $result  = self::sessionsOf($guard)->signIn('password', self::credentials(), $context);

        self::assertTrue($result->isPending());
        self::assertFalse($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertSame(SignInStatus::PENDING, $result->status);
        self::assertNull($result->session);
        self::assertNull($result->reason);
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);
        self::assertSameModel($identity, $result->pending->identity);
        self::assertSameModel($identity, $result->pending->principal);
        self::assertSame([PendingRequirement::MFA], $result->pending->requires);
        self::assertSame('password', $result->pending->method);
        self::assertSame('api', $result->pending->guard);

        $pending = Session::query()->sole();

        self::assertSame(SessionStatus::PENDING, $pending->getStatus());
        self::assertSame([['sign-in' => '2026-04-06 12:05:00'], ['account' => '2026-04-06 12:05:00']], $pending->attempt_windows);
        self::assertSame([], $this->recordedClasses());
        self::assertFalse($guard->hasUser());

        self::assertInstanceOf(AdditionalFactorContext::class, $asked);
        self::assertSame('api', $asked->application);
        self::assertSameModel($identity, $asked->identity);
        self::assertSame('password', $asked->firstFactor->method);
        self::assertSame(ChannelKind::PASSWORD, $asked->firstFactor->channel->kind);
        self::assertSame($context->client, $asked->client);
        self::assertSame('Phone', $asked->clientName);
        self::assertSame('iOS', $asked->platform);
        self::assertNull($asked->provenSession);
    }

    /**
     * A sign-in acting within a tenant carries that tenant on, though the
     * identity-level factor policy is not told of it: `SessionCreated` and
     * `SignedIn` carry it when the session starts (the first sign-in), and the
     * pending session, its record and `SessionPending` when a further factor is
     * required (the second).
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInWithinATenantCarriesTheTenantOn(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $asked = [];

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->twice()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): Requirement {
            $asked[] = $context->identity;

            return count($asked) === 2 ? new Requirement(new RequirementPart) : new Requirement;
        });

        $this->recordEvents([SessionCreated::class, SignedIn::class, SessionPending::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSameModel($membership, $session->principal);
        EventContextAssertions::assertTenant($tenant, $this->recordedEvent(SessionCreated::class)->context);
        EventContextAssertions::assertTenant($tenant, $this->recordedEvent(SignedIn::class)->context);

        $pending = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->pending;

        self::assertNotNull($pending);
        self::assertSameModel($tenant, $pending->tenant);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $pending->session->getTenantId());
        EventContextAssertions::assertTenant($tenant, $this->recordedEvent(SessionPending::class)->context);
        self::assertCount(2, $asked);
    }

    /**
     * The session's deadlines follow the lifetimes the application policy gives
     * the guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeadlinesFollowTheApplicationPolicysLifetimes(): void
    {
        $this->seedIdentity();

        $policy = $this->policy();
        $policy->shouldReceive('lifetimes')->once()->with('api')->andReturn(new TokenLifetimes(5, 60, 120, 30));

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSame($this->now->addHour()->getTimestamp(), $session->record->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addHours(2)->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * A password sign-in rehashes an outdated hash once admitted; a sign-in
     * through another method never touches the password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyThePasswordMethodRehashes(): void
    {
        $identity = $this->seedIdentity();

        $identity->forceFill(['password' => password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 5])])->save();

        $outdated = $this->storedHash($identity);

        $this->registerTrustedMethod($identity);

        self::assertTrue($this->sessions()->signIn('trusted', [], self::requestContext())->isSignedIn());
        self::assertSame($outdated, $this->storedHash($identity));

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
        self::assertNotSame($outdated, $this->storedHash($identity));
    }

    /**
     * A method without an identifier type reports its identifier under
     * `identifier`, and one that names no identifier reports none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodWithoutAnIdentifierTypeReportsItsIdentifierGenerically(): void
    {
        $identity = $this->seedIdentity();

        $this->registerTrustedMethod($identity, 'ada');
        $this->recordEvents([Attempting::class, AuthenticationFailed::class]);

        self::assertTrue($this->sessions()->signIn('trusted', [], self::requestContext())->isSignedIn());
        self::assertSame(['identifier' => 'ada'], $this->recordedEvent(Attempting::class)->credentials);

        $this->registerTrustedMethod(null);
        $this->recordEvents([Attempting::class, AuthenticationFailed::class]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('trusted', [], self::requestContext())->reason);
        self::assertSame([], $this->recordedEvent(Attempting::class)->credentials);
        self::assertNull($this->recordedEvent(AuthenticationFailed::class)->identifier);
    }

    /**
     * A sign-in method may refuse only with `invalid_credentials`: any other
     * reason is the session service's to give, so a method that answers with
     * one is misconfigured and fails loudly instead of reporting a reason it
     * cannot know.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodThatRefusesWithAServiceReasonIsAMisconfiguration(): void
    {
        $this->registerTrustedMethod(FailureReason::SESSION_REVOKED);
        $this->recordEvents([AuthenticationFailed::class]);

        try {
            $this->sessions()->signIn('trusted', [], self::requestContext());
            self::fail('Expected a LogicException.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('`session_revoked`', $exception->getMessage());
            self::assertStringContainsString('`invalid_credentials`', $exception->getMessage());
        }

        self::assertSame([], $this->recorded);
    }

    /**
     * `start()` begins a session for an identity verified elsewhere: it is
     * reloaded through the guard's provider, the method is recorded, and no
     * `Attempting`, limit or rehash applies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartBeginsASessionForAnExternallyVerifiedIdentity(): void
    {
        $identity = $this->seedIdentity();
        $stale    = IntegrationIdentity::query()->findOrFail($identity->getKey());

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldNotReceive('acquire');

        $this->recordEvents([Attempting::class, Validated::class, SessionCreated::class, SignedIn::class]);

        $result = $this->sessions()->start(UndescribedFirstFactor::of($stale), null, 'sso', self::requestContext());

        self::assertTrue($result->isSignedIn());
        $session = self::sessionOf($result);

        self::assertNotSame($stale, $session->identity);
        self::assertSameModel($identity, $session->identity);
        self::assertSame('sso', $session->record->getSignInMethod());
        self::assertSame([SessionCreated::class, SignedIn::class, Validated::class], $this->recordedClasses());
        self::assertSame('sso', $this->recordedEvent(SignedIn::class)->context->method);
    }

    /**
     * `start()` refuses an identity the guard's provider does not return as
     * that very identity and a method the guard does not allow, and hands out a
     * pending session when the factor policy asks a factor of it, so a sign-in
     * verified elsewhere cannot skip the factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRefusesWhatSignInWouldRefuse(): void
    {
        $identity = $this->seedIdentity();
        $unsaved  = new IntegrationIdentity;

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        $this->assertSignInFails(FailureReason::IDENTITY_UNKNOWN, $this->sessions()->start(UndescribedFirstFactor::of($unsaved), null, 'sso', self::requestContext()));
        self::assertSame($unsaved, $this->recordedEvent(Failed::class)->user);
        self::assertSame([], $this->recordedEvent(Failed::class)->credentials);

        $policy = $this->policy();
        $policy->shouldReceive('allowsMethod')->with('api', 'sso')->andReturnFalse();

        $this->assertSignInFails(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext()));

        $policy->shouldReceive('allowsMethod')->with('api', 'otp')->andReturnTrue();

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->once()->andReturn(new Requirement(new RequirementPart));

        $pending = $this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'otp', self::requestContext());

        self::assertTrue($pending->isPending());
        self::assertSame('otp', $pending->pending?->method);
        self::assertSame(0, Session::query()->where('status', 'active')->count());
    }

    /**
     * `start()` records the first factor it is given as the session's first
     * proof: its channel and reference, observed properties and `amr` values,
     * timed by the server and never multifactor, and the access token says so.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRecordsTheFirstFactorItWasGiven(): void
    {
        $identity = $this->seedIdentity();
        $factor   = new FirstFactor($identity, new Channel(ChannelKind::PASSWORD), new ObservedProperties(userVerification: true), ['pwd']);
        $result   = $this->sessions()->start($factor, null, 'sso', self::requestContext());
        $session  = $result->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(1, $proofs);
        self::assertSame(
            [ProofKind::FIRST_FACTOR->value, 'sso', ChannelKind::PASSWORD->value, ['pwd'], true],
            [$proofs[0]->kind, $proofs[0]->method, $proofs[0]->channel_kind, $proofs[0]->methods, $proofs[0]->user_verification],
        );
        self::assertSame($this->now->getTimestamp(), $proofs[0]->authenticated_at->getTimestamp());

        $claims = Auth::manager()->jwt('api')->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame(['pwd'], $claims['amr']);
        self::assertSame($this->now->getTimestamp(), $claims['auth_time']);
    }

    /**
     * The application's own recovery is recorded as the first factor over the
     * recovery channel: still a first factor, and never multifactor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRecordsTheApplicationsOwnRecoveryAsAFirstFactor(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->start(new FirstFactor($identity, new Channel(ChannelKind::RECOVERY)), null, 'sso', self::requestContext())->session;

        self::assertNotNull($session);

        $proofs = self::proofsOf($session->record);

        self::assertCount(1, $proofs);
        self::assertSame([ProofKind::FIRST_FACTOR->value, ChannelKind::RECOVERY->value, []], [$proofs[0]->kind, $proofs[0]->channel_kind, $proofs[0]->methods]);

        $claims = Auth::manager()->jwt('api')->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertNotContains('mfa', $claims['amr'] ?? []);
    }

    /**
     * A session `start()` began after a password the application checked itself
     * is judged as a password sign-in is: the further-factor policy is asked
     * about the password channel and its `amr`, and a further factor it waits
     * on is then accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartedPasswordSessionIsJudgedAsAPasswordSignInIsAndTakesAFurtherFactor(): void
    {
        $identity = $this->seedIdentity();
        $asked    = null;

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->atLeast()->once()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): Requirement {
            $asked = $context;

            return new Requirement(new RequirementPart);
        });
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->sessions()->start(new FirstFactor($identity, new Channel(ChannelKind::PASSWORD), methods: ['pwd']), null, 'password', self::requestContext());

        self::assertTrue($pending->isPending());
        self::assertInstanceOf(AdditionalFactorContext::class, $asked);
        self::assertSame([ChannelKind::PASSWORD, ['pwd']], [$asked->firstFactor->channel->kind, $asked->firstFactor->methods]);
        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $result = $this->sessions()->satisfy($pending->credential->reveal(), self::adapterProof($identity, 'api', $pending->pending->id, Purpose::SIGN_IN), self::requestClient());

        self::assertTrue($result->isSignedIn());

        $claims = Auth::manager()->jwt('api')->parse((string) $result->session?->tokens->accessToken->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertContains('pwd', $claims['amr']);
        self::assertContains('otp', $claims['amr']);
    }

    /**
     * Rows of `[channel kind, amr values]`: what only an external provider's
     * result makes.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind, 1: list<string>}>
     */
    public static function provideExternalProviderFirstFactors(): iterable
    {
        yield 'its channel' => [ChannelKind::EXTERNAL_PROVIDER, []];
        yield 'its amr value' => [ChannelKind::UNKNOWN, [FirstFactor::EXTERNAL_PROVIDER_METHOD]];
    }

    /**
     * `start()` refuses a first factor that stands for an external provider's,
     * and records nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $kind
     * @param  list<string>  $methods
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExternalProviderFirstFactors')]
    public function testStartRefusesAFirstFactorStandingForAnExternalProvider(ChannelKind $kind, array $methods): void
    {
        $factor = new FirstFactor($this->seedIdentity(), new Channel($kind), methods: $methods);

        try {
            $this->sessions()->start($factor, null, 'sso', self::requestContext());

            self::fail('A session was started from an external provider\'s first factor.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(SessionPreconditions::EXTERNAL_FACTOR_MESSAGE, $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * A first factor whose `amr` names `mfa` cannot be made, so `start()` is
     * never handed one: a channel never implies multifactor authentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFirstFactorNamingMultifactorCannotBeMade(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new FirstFactor($this->seedIdentity(), new Channel(ChannelKind::PASSWORD), methods: ['pwd', 'mfa']);
    }

    /**
     * Rows of `[credential kind]`: what an application may list that is not a
     * sign-in method.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCredentialKinds(): iterable
    {
        yield from [
            'an API key'         => ['api_key'],
            'client credentials' => ['client_credentials'],
        ];
    }

    /**
     * `start()` refuses a machine credential kind as the method, even on a
     * guard whose application lists it: no session is recorded under it, so
     * none passes for a machine credential.
     *
     * @param  string  $kind
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCredentialKinds')]
    public function testStartRefusesAMachineCredentialKindAsTheMethod(string $kind): void
    {
        $identity = $this->seedIdentity();

        config()->set('auth.guards.api.application', ['methods' => ['password', $kind]]);

        try {
            $this->sessions()->start(UndescribedFirstFactor::of($identity), null, $kind, self::requestContext());

            self::fail('A session was started under a machine credential kind.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("[{$kind}] names a machine credential, not a sign-in method; no session can be started with it.", $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * `start()` refuses `external_provider` as the method, even on a guard
     * whose application allows external sign-in: a session is recorded under it
     * only from an external result the link contract maps to its identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRefusesTheExternalProviderMethod(): void
    {
        $identity = $this->seedIdentity();

        try {
            $this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'external_provider', self::requestContext());

            self::fail('A session was started under external_provider.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('[external_provider] is not a sign-in method: only a result an external provider verified signs a session in under it.', $exception->getMessage());
        }

        self::assertSame(0, Session::query()->count());
    }

    /**
     * `start()` checks the identity's provider: an identity of another model
     * that shares the key is not the guard's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRefusesAnIdentityOfAnotherModelWithTheSameKey(): void
    {
        [$member] = $this->seedMember();

        $this->seedIdentity();

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $this->sessions()->start(UndescribedFirstFactor::of($member), null, 'sso', self::requestContext())->reason);
    }

    /**
     * `start()` acts as a principal given as the argument or on the context,
     * proven to be the identity's own, and refuses both at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartActsAsTheGivenPrincipal(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();
        [, $foreign]                    = $this->seedMember('other@example.test', $tenant);

        $context = new SignInContext(new ClientContext(null, null), principal: $membership);

        $started = $this->sessions('members')->start(UndescribedFirstFactor::of($member), $membership, 'sso', self::requestContext());

        self::assertSameModel($membership, self::sessionOf($started)->principal);
        self::assertSameModel($membership, self::sessionOf($this->sessions('members')->start(UndescribedFirstFactor::of($member), null, 'sso', $context))->principal);
        $mismatch = $this->sessions('members')->start(UndescribedFirstFactor::of($member), $foreign, 'sso', self::requestContext());

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $mismatch->reason);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Name the principal to start a session as either as the argument or on the context, not both.');

        $this->sessions('members')->start(UndescribedFirstFactor::of($member), $membership, 'sso', $context);
    }

    /**
     * Signing in an identity that does not own sessions fails as the
     * misconfiguration it is, naming the identity class, and writes no session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInRefusesAnIdentityWithoutSessions(): void
    {
        $this->seedIdentityWithoutSessions();

        $this->expectRefusalOfIdentitiesWithoutSessions();

        try {
            $this->sessions('plain')->signIn('password', self::credentials(), self::requestContext());
        } finally {
            self::assertSame(0, Session::query()->count());
        }
    }

    /**
     * Starting a session for an identity that does not own sessions fails the
     * same way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRefusesAnIdentityWithoutSessions(): void
    {
        $identity = $this->seedIdentityWithoutSessions();

        $this->expectRefusalOfIdentitiesWithoutSessions();

        $this->sessions('plain')->start(UndescribedFirstFactor::of($identity), null, 'password', self::requestContext());
    }

    /**
     * Whatever limiter is bound, one that throws when a pending session's first
     * activation gives its sign-in's slots back has its error reported, not
     * thrown: `satisfy()` returns the activated session, the guard is bound,
     * and the slots after the one that failed are not given back either.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationReportsALimiterThatCannotGiveTheSlotsBack(): void
    {
        $identity = $this->seedIdentity();

        $failure    = new \RuntimeException('The counters are unreachable.');
        $exceptions = Exceptions::fake([\RuntimeException::class]);
        $limiter    = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, null, ['slot' => 'window']));
        $limiter->shouldReceive('release')->once()->andThrow($failure);

        [$credential, $proof] = $this->pendingWithProof($identity);

        $result = Auth::sessions('api')->satisfy($credential, $proof, self::requestClient());

        self::assertTrue($result->isSignedIn());
        self::assertSame($identity->getKey(), Auth::guard('api')->id());
        self::assertSame([$failure], $exceptions->reported());
    }

    /**
     * Rows of `[bind event]`: each event a sign-in's bind dispatches.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideBindEvents(): iterable
    {
        yield from [
            'Validated'            => [Validated::class],
            'Login'                => [Login::class],
            'Authenticated'        => [Authenticated::class],
            'PrincipalAssigned'    => [PrincipalAssigned::class],
            'SessionAuthenticated' => [SessionAuthenticated::class],
        ];
    }

    /**
     * A listener that throws on any bind event fails the sign-in after its
     * session committed, but cannot withhold the session's report:
     * `SessionCreated` and `SignedIn` were dispatched, once, before the bind,
     * and the listener's exception reaches the caller.
     *
     * @param  class-string  $bindEvent
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBindEvents')]
    public function testASignInWhoseBindListenerThrowsIsStillReported(string $bindEvent): void
    {
        $this->seedIdentity();

        $this->recordEvents([SessionCreated::class, SignedIn::class, $bindEvent]);

        Event::listen($bindEvent, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        self::assertSame('listener failed', self::failureOf(fn (): SignInResult => $this->sessions()->signIn('password', self::credentials(), self::requestContext())));
        self::assertSame([SessionCreated::class, SignedIn::class, $bindEvent], $this->recordedClasses());
        self::assertSame(1, Session::query()->count());
    }

    /**
     * A session `start()` began is reported the same way when a bind listener
     * throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartedSessionWhoseBindListenerThrowsIsStillReported(): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        $factor = UndescribedFirstFactor::of($identity);

        self::assertSame('listener failed', self::failureOf(fn (): SignInResult => $this->sessions()->start($factor, null, 'sso', self::requestContext())));
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame('sso', $this->recordedEvent(SignedIn::class)->context->method);
    }

    /**
     * An activation whose bind listener throws is reported, its report being
     * scheduled before the bind, but keeps the slots its sign-in took counted:
     * they are given back only once the bind returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationWhoseBindListenerThrowsIsStillReportedAndKeepsItsSlots(): void
    {
        $identity = $this->seedIdentity();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        [$credential, $proof] = $this->pendingWithProof($identity);

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        Event::listen(Authenticated::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        self::assertSame('listener failed', self::failureOf(fn (): SignInResult => $this->sessions()->satisfy($credential, $proof, self::requestClient())));
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertCount(0, $limiter->released);
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
    }

    /**
     * An activation gives back, once it has bound the session, exactly the
     * slots its sign-in held while pending: one for each window the session
     * kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationGivesBackTheSlotsItsSignInHeldOnceBound(): void
    {
        $identity = $this->seedIdentity();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        [$credential, $proof] = $this->pendingWithProof($identity);

        $held = $limiter->reservations;

        Event::listen(Login::class, static function () use ($limiter): void {
            self::assertCount(0, $limiter->released);
        });

        self::assertTrue($this->sessions()->satisfy($credential, $proof, self::requestClient())->isSignedIn());
        self::assertCount(count($held), $limiter->released);
        $windows = static fn (AttemptReservation $reservation): array => $reservation->windows;

        self::assertSame(array_map($windows, $held), array_map($windows, $limiter->released));
    }

    /**
     * Inside a caller's transaction, an activation binds nothing until the
     * caller commits: a rollback withdraws its report and its bind with the
     * activation and leaves the session pending, so its credential can satisfy
     * it again; a commit reports the session, then binds it, and the bind
     * listener's exception reaches the caller's commit, leaving the slots
     * counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActivationWhoseBindListenerThrowsFollowsTheCallersTransaction(): void
    {
        $identity = $this->seedIdentity();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        [$credential, $proof] = $this->pendingWithProof($identity);

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        Event::listen(Authenticated::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        $satisfy = fn (): SignInResult => $this->sessions()->satisfy($credential, $proof, self::requestClient());

        DB::beginTransaction();

        self::assertTrue($satisfy()->isSignedIn());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertCount(0, $limiter->released);
        self::assertSame(SessionStatus::PENDING, Session::query()->sole()->getStatus());
        self::assertFalse(Auth::guard('api')->hasUser());

        DB::beginTransaction();

        self::assertTrue($satisfy()->isSignedIn());
        self::assertSame([], $this->recordedClasses());

        try {
            DB::commit();

            self::fail('Expected the bind listener to throw at the commit.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertCount(0, $limiter->released);
        self::assertSame(SessionStatus::ACTIVE, Session::query()->sole()->getStatus());
    }

    /**
     * A satisfaction inside a caller's transaction binds the guard only when it
     * commits: one that rolls back binds nothing, dispatches no `Login` and
     * keeps the slots counted; one that commits binds once, with one `Login`,
     * then gives the slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASatisfactionBindsTheGuardOnlyOnceItCommits(): void
    {
        $identity = $this->seedIdentity();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        [$credential, $proof] = $this->pendingWithProof($identity);

        $this->recordEvents([Login::class]);

        $sessions = $this->sessions();
        $guard    = Auth::guard('api');

        DB::beginTransaction();

        self::assertTrue($sessions->satisfy($credential, $proof, self::requestClient())->isSignedIn());
        self::assertFalse($guard->hasUser());

        DB::rollBack();

        self::assertFalse($guard->hasUser());
        self::assertSame([], $this->recordedClasses());
        self::assertCount(0, $limiter->released);

        DB::transaction(static fn (): bool => $sessions->satisfy($credential, $proof, self::requestClient())->isSignedIn());

        self::assertSame($identity->getKey(), $guard->id());
        self::assertSame([Login::class], $this->recordedClasses());
        self::assertCount(count($limiter->reservations), $limiter->released);
    }

    /**
     * Rows of what the caller's transaction does to the session after the
     * sign-in, before it commits.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesBeforeTheCommit(): iterable
    {
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'signed_out']];
        yield 'returned to pending' => [['status' => 'pending']];
        yield 'another session put under its key' => [['generation' => '00000000-0000-7000-8000-000000000000']];
        yield 'switched to another principal' => [['principal_id' => '999999']];
        yield 'switched to another tenant' => [['tenant_id' => 'another-tenant']];
    }

    /**
     * A bind that waited for the commit reads the session again first: one the
     * same transaction revoked, returned to pending, replaced or switched to
     * another principal or tenant is never bound, though its sign-in is
     * reported and its slots given back.
     *
     * @param  array<string, mixed>  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesBeforeTheCommit')]
    public function testABindThatWaitedIsNotMadeForASessionChangedBeforeTheCommit(array $change): void
    {
        $this->seedIdentity();

        $limiter = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([SignedIn::class, Login::class]);

        $sessions = $this->sessions();

        DB::transaction(static function () use ($sessions, $change): void {
            self::assertTrue($sessions->signIn('password', self::credentials(), self::requestContext())->isSignedIn());

            DB::table('authentication_sessions')->update($change);
        });

        self::assertFalse(Auth::guard('api')->hasUser());
        self::assertSame([SignedIn::class], $this->recordedClasses());
        self::assertCount(count($limiter->reservations), $limiter->released);
    }

    /**
     * A transaction open on another connection neither delays nor withdraws the
     * bind: the session's writes were not made in it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionDoesNotDelayTheBind(): void
    {
        $this->seedIdentity();

        $elsewhere = DB::connection('elsewhere');

        $elsewhere->beginTransaction();

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
        self::assertTrue(Auth::guard('api')->hasUser());

        $elsewhere->rollBack();

        self::assertTrue(Auth::guard('api')->hasUser());
    }

    /**
     * A lifecycle listener that throws propagates as any listener does: with no
     * transaction open it runs before the bind, so the session stands but the
     * guard is not bound to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALifecycleListenerThatThrowsStopsTheBind(): void
    {
        $this->seedIdentity();

        $this->recordEvents([Login::class]);

        Event::listen(SignedIn::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        $guard = $this->freshGuard();

        self::assertSame(
            'listener failed',
            self::failureOf(static fn (): SignInResult => self::sessionsOf($guard)->signIn('password', self::credentials(), self::requestContext())),
        );
        self::assertSame([], $this->recordedClasses());
        self::assertFalse($guard->hasUser());
        self::assertSame(1, Session::query()->count());
    }

    /**
     * A password sign-in or a started session for an identity the application
     * admits as several principals waits for the identity to choose one, with
     * the principals listed, and binds nothing; with only one, that one is
     * selected and the session starts, whatever the resolver's default.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInOrAStartWithSeveralPrincipalsWaitsForAChoice(): void
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $tenant = ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);
        $first  = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        self::assertTrue($this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'), self::requestContext())->isSignedIn());

        $second = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        Auth::forgetGuards();

        $signedIn = $this->sessions('choosers')->signIn('password', self::credentials('chooser@example.test'), self::requestContext());
        $started  = $this->sessions('choosers')->start(UndescribedFirstFactor::of($member), null, 'sso', self::requestContext());

        foreach ([$signedIn, $started] as $result) {
            self::assertTrue($result->isPending());
            self::assertNotNull($result->pending);
            self::assertSame([PendingRequirement::PRINCIPAL], $result->pending->requires);
            self::assertNull($result->pending->principal);
            self::assertSame(
                [$first->getKey(), $second->getKey()],
                array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $result->pending->principals),
            );
        }

        self::assertSame(2, Session::query()->where('status', 'pending')->count());
        self::assertTrue(app('auth')->guard('choosers')->guest());
    }

    /**
     * Rows of the headers a request to a cookie application sends that does not
     * come from a page of its own site, each fact failing alone.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideCrossSiteHeaders(): iterable
    {
        yield 'another site\'s form' => [['Origin' => 'https://evil.example.test']];
        yield 'another site with the header' => [['Origin' => 'https://evil.example.test', 'X-Requested-With' => 'fetch']];
        yield 'an allowed origin without the header' => [['Origin' => self::ALLOWED_ORIGIN]];
        yield 'the own origin without the header' => [['Origin' => self::OWN_ORIGIN]];
        yield 'the own origin with an empty header' => [['Origin' => self::OWN_ORIGIN, 'X-Requested-With' => '']];
        yield 'the header without an origin' => [['X-Requested-With' => 'fetch']];
        yield 'neither' => [[]];
    }

    /**
     * A cookie application's sign-in that does not come from a page of its own
     * site is refused as `cross_site_request` before the method policy is asked
     * or an attempt counted, so the input is never checked: it writes no
     * session or proof, binds nothing, and is reported after `Attempting` by
     * `Failed` and `AuthenticationFailed` (flow `sign_in`, with the identifier
     * and the request's client, no identity).
     *
     * @param  array<string, string>  $headers
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteHeaders')]
    public function testACookieApplicationRefusesACrossSiteSignInBeforeAnythingIsChecked(array $headers): void
    {
        $this->seedIdentity();

        $policy = $this->policy();
        $policy->shouldNotReceive('allowsMethod');

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldNotReceive('acquire');

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class, Login::class]);

        $this->assertSignInFails(FailureReason::CROSS_SITE_REQUEST, $this->sessionsOn(self::BROWSER, $headers)->signIn('password', self::credentials(), self::requestContext()));

        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertNull($this->recordedEvent(Failed::class)->user);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::SIGN_IN, FailureReason::CROSS_SITE_REQUEST, 'ada@example.test'], [$failed->flow, $failed->reason, $failed->identifier]);
        self::assertSame([self::BROWSER, null, $headers['Origin'] ?? null], [$failed->context->guard, $failed->context->identityId, $failed->context->client->origin]);
        self::assertSame(0, DB::table('authentication_proofs')->count());
        self::assertTrue(app('auth')->guard(self::BROWSER)->guest());
    }

    /**
     * Rows of the headers a page of a cookie application's own site sends: the
     * request's own origin or an allowed one, with the custom header.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideSameSiteHeaders(): iterable
    {
        yield 'the own origin' => [['Origin' => self::OWN_ORIGIN, 'X-Requested-With' => 'fetch']];
        yield 'an allowed origin' => [['Origin' => self::ALLOWED_ORIGIN, 'X-Requested-With' => 'fetch']];
    }

    /**
     * A cookie application's sign-in from the request's own origin or an
     * allowed one, with the custom header, signs in and hands the refresh token
     * over only in its cookie.
     *
     * @param  array<string, string>  $headers
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSameSiteHeaders')]
    public function testACookieApplicationSignsInFromItsOwnSite(array $headers): void
    {
        $identity = $this->seedIdentity();
        $tokens   = self::sessionOf($this->sessionsOn(self::BROWSER, $headers)->signIn('password', self::credentials(), self::requestContext()))->tokens;

        self::assertNull($tokens->refreshToken);
        self::assertNotNull($tokens->refreshCookie);
        self::assertSame($identity->getKey(), app('auth')->guard(self::BROWSER)->id());
    }

    /**
     * A cross-site sign-in fails with no challenge named, since the input was
     * never checked, while a same-site one the method refuses names the
     * challenge its input answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACrossSiteSignInNamesNoChallenge(): void
    {
        $this->registerTrustedMethod(FailureReason::INVALID_CREDENTIALS);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            FailureReason::CROSS_SITE_REQUEST,
            $this->sessionsOn(self::BROWSER, [])->signIn('trusted', ['challenge' => 'challenge-1'], self::requestContext())->reason,
        );
        self::assertNull($this->recordedEvent(AuthenticationFailed::class)->challengeId);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            $this->sessionsOn(self::BROWSER, self::SAME_SITE)->signIn('trusted', ['challenge' => 'challenge-1'], self::requestContext())->reason,
        );
        self::assertSame('challenge-1', $this->recordedEvent(AuthenticationFailed::class)->challengeId);
    }

    /**
     * `signIn()` judges the client of the context it is given, not the
     * request's: one built from plain values without the same-site facts is
     * refused on a same-site request, and one built with them passes on a
     * cross-site request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInJudgesTheContextsClient(): void
    {
        $this->seedIdentity();

        $plain  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT));
        $facts  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT, self::OWN_ORIGIN, self::OWN_ORIGIN, ['X-Requested-With']));
        $result = $this->sessionsOn(self::BROWSER, self::SAME_SITE)->signIn('password', self::credentials(), $plain);

        $this->assertSignInFails(FailureReason::CROSS_SITE_REQUEST, $result);

        self::assertTrue($this->sessionsOn(self::BROWSER, [])->signIn('password', self::credentials(), $facts)->isSignedIn());
    }

    /**
     * One guard judges each context it is given on its own, keeping nothing
     * from the last: after signing a same-site context in, it refuses a
     * cross-site context it is handed next, and signs the same-site one in
     * again, while it serves the same request throughout.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneGuardJudgesEachContextItIsGivenOnItsOwn(): void
    {
        $this->seedIdentity();

        $sessions  = $this->sessionsOn(self::BROWSER, self::SAME_SITE);
        $guard     = app('auth')->guard(self::BROWSER);
        $sameSite  = SignInContext::fromRequest(self::requestWith(self::SAME_SITE));
        $crossSite = SignInContext::fromRequest(self::requestWith(['Origin' => 'https://evil.example.test']));

        self::assertTrue($sessions->signIn('password', self::credentials(), $sameSite)->isSignedIn());
        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $sessions->signIn('password', self::credentials(), $crossSite)->reason);
        self::assertTrue($sessions->signIn('password', self::credentials(), $sameSite)->isSignedIn());
        self::assertSame($guard, app('auth')->guard(self::BROWSER));
        self::assertSame(2, Session::query()->count());
    }

    /**
     * A cookie application's `start()` that does not come from a page of its
     * own site is refused as `cross_site_request` before anything is read,
     * reported by `Failed` and `AuthenticationFailed` with no `Attempting`, and
     * writes nothing; one built from plain values is refused too, and a
     * same-site one starts the session with the cookie.
     *
     * @param  array<string, string>  $headers
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteHeaders')]
    public function testACookieApplicationRefusesACrossSiteStart(array $headers): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class]);

        $factor = UndescribedFirstFactor::of($identity);

        $this->assertSignInFails(FailureReason::CROSS_SITE_REQUEST, $this->sessionsOn(self::BROWSER, $headers)->start($factor, null, 'sso', self::requestContext()));

        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::SIGN_IN, 'sso'], [$failed->flow, $failed->context->method]);

        $plain = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT));

        $sameSite = $this->sessionsOn(self::BROWSER, self::SAME_SITE);

        $this->assertSignInFails(FailureReason::CROSS_SITE_REQUEST, $sameSite->start(UndescribedFirstFactor::of($identity), null, 'sso', $plain));

        $started = $sameSite->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext());

        self::assertNotNull(self::sessionOf($started)->tokens->refreshCookie);
    }

    /**
     * A cookie application's satisfaction that does not come from a page of its
     * own site is refused as `cross_site_request` before the pending session is
     * read: the session stays pending, the proof unstored and the credential
     * unconsumed, so the same satisfaction from the application's own site then
     * activates it with the cookie.
     *
     * @param  array<string, string>  $headers
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteHeaders')]
    public function testACookieApplicationRefusesACrossSiteSatisfaction(array $headers): void
    {
        $identity             = $this->seedIdentity();
        [$credential, $proof] = $this->pendingWithProof($identity, self::BROWSER);
        $proofs               = DB::table('authentication_proofs')->count();

        $this->recordEvents([Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class]);

        $refused = $this->sessionsOn(self::BROWSER, $headers)->satisfy($credential, $proof, self::requestClient());

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $refused->reason);
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertNull($this->recordedEvent(AuthenticationFailed::class)->context->sessionId);
        self::assertSame([SessionStatus::PENDING->value], Session::query()->pluck('status')->all());
        self::assertSame($proofs, DB::table('authentication_proofs')->count());
        self::assertTrue(app('auth')->guard(self::BROWSER)->guest());

        $activated = self::sessionOf($this->sessionsOn(self::BROWSER, self::SAME_SITE)->satisfy($credential, $proof, self::requestClient()));

        self::assertNotNull($activated->tokens->refreshCookie);
        self::assertSame([SessionStatus::ACTIVE->value], Session::query()->pluck('status')->all());
    }

    /**
     * A cookie application's choice of principal that does not come from a page
     * of its own site is refused as `cross_site_request` before the pending
     * session is read: no principal is recorded and the session stays pending,
     * so the same choice from the application's own site then activates it with
     * the cookie.
     *
     * @param  array<string, string>  $headers
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteHeaders')]
    public function testACookieApplicationRefusesACrossSiteChoice(array $headers): void
    {
        [$credential, $chosen] = $this->pendingChoice(self::BROWSER_CHOOSERS);

        $this->recordEvents([Failed::class, AuthenticationFailed::class, PrincipalAssigned::class]);

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $this->sessionsOn(self::BROWSER_CHOOSERS, $headers)->choose($credential, $chosen, self::requestClient())->reason);
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame([SessionStatus::PENDING->value], Session::query()->pluck('status')->all());
        self::assertSame([null], Session::query()->pluck('principal_id')->all());

        $activated = self::sessionOf($this->sessionsOn(self::BROWSER_CHOOSERS, self::SAME_SITE)->choose($credential, $chosen, self::requestClient()));

        self::assertNotNull($activated->tokens->refreshCookie);
        self::assertSame($chosen->getKey(), $activated->principal->getPrincipalIdentifier());
    }

    /**
     * A cookie application's satisfaction given a same-site client, as a
     * service layer that keeps HTTP out gives it, is judged on that client
     * alone: it activates the session with the cookie though the guard's own
     * request comes from another site, the client written as its last use and
     * carried by the events that report it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationSatisfiesForASameSiteClientGiven(): void
    {
        $identity             = $this->seedIdentity();
        [$credential, $proof] = $this->pendingWithProof($identity, self::BROWSER);
        $client               = self::sameSiteClient();

        $this->recordEvents([SessionCreated::class, SignedIn::class]);

        $activated = self::sessionOf($this->sessionsOn(self::BROWSER, ['Origin' => 'https://evil.example.test'])->satisfy($credential, $proof, $client));

        self::assertNotNull($activated->tokens->refreshCookie);
        self::assertNull($activated->tokens->refreshToken);
        self::assertSame([SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(SignedIn::class)->context->client);
        self::assertSame(self::PLAIN_IP, Session::query()->sole()->getRawOriginal('last_used_ip'));
    }

    /**
     * The guard's bind after an activation given a client describes that
     * client, not the guard's own request: with a last-use throttle that
     * records every use, its `PrincipalAssigned` and `SessionAuthenticated`
     * carry the client given and the session's last use stays the one the
     * activation wrote.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsBindAfterASatisfactionDescribesTheClientGiven(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 0);

        $identity             = $this->seedIdentity();
        [$credential, $proof] = $this->pendingWithProof($identity, self::BROWSER);
        $client               = self::sameSiteClient();

        $this->recordEvents([SignedIn::class, PrincipalAssigned::class, SessionAuthenticated::class]);

        self::assertTrue($this->sessionsOn(self::BROWSER, ['Origin' => 'https://evil.example.test'])->satisfy($credential, $proof, $client)->isSignedIn());

        $session = Session::query()->sole();

        self::assertSame($client, $this->recordedEvent(SignedIn::class)->context->client);
        self::assertSame($client, $this->recordedEvent(PrincipalAssigned::class)->context->client);
        self::assertSame($client, $this->recordedEvent(SessionAuthenticated::class)->context->client);
        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], [$session->getRawOriginal('last_used_ip'), $session->getRawOriginal('last_used_user_agent')]);
    }

    /**
     * The guard's bind after a choice given a client describes that client, as
     * a satisfaction's does: its bind events carry it, and with a last-use
     * throttle that records every use the session's last use stays that
     * client's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsBindAfterAChoiceDescribesTheClientGiven(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 0);

        $client            = self::sameSiteClient();
        [$choice, $chosen] = $this->pendingChoice(self::BROWSER_CHOOSERS);

        $this->recordEvents([PrincipalAssigned::class, SessionAuthenticated::class]);

        self::assertTrue($this->sessionsOn(self::BROWSER_CHOOSERS, ['Origin' => 'https://evil.example.test'])->choose($choice, $chosen, $client)->isSignedIn());

        $chosenSession = Session::query()->sole();

        self::assertSame($client, $this->recordedEvent(PrincipalAssigned::class)->context->client);
        self::assertSame($client, $this->recordedEvent(SessionAuthenticated::class)->context->client);
        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], [$chosenSession->getRawOriginal('last_used_ip'), $chosenSession->getRawOriginal('last_used_user_agent')]);
    }

    /**
     * Rows of `[a sign-in of the seeded identity through the service]`: by
     * password, and started for the identity verified outside the guard.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \Tests\Integration\Fixtures\IntegrationIdentity): \SineMacula\Laravel\Authentication\Sessions\SignInResult}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideSignIns(): iterable
    {
        yield 'signIn()' => [static fn (SessionService $sessions): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext())];
        yield 'start()' => [
            static fn (SessionService $sessions, IntegrationIdentity $identity): SignInResult => $sessions->start(
                UndescribedFirstFactor::of($identity),
                null,
                'sso',
                self::requestContext(),
            ),
        ];
    }

    /**
     * A sign-in whose identity is deactivated after its admission, before its
     * session is written, is refused once the session commits: the session is
     * revoked as `identity_deactivated` without a `SessionRevoked` (it was
     * never handed out), the refusal is reported as every refused sign-in is,
     * nothing reports the session, the guard is not bound to it, and the
     * attempt-limit slots the sign-in took stay counted.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \Tests\Integration\Fixtures\IntegrationIdentity): \SineMacula\Laravel\Authentication\Sessions\SignInResult  $signIn
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSignIns')]
    public function testASignInWhoseIdentityIsDeactivatedBeforeItsWriteIsRefusedAndEnded(\Closure $signIn): void
    {
        $identity = $this->seedIdentity();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        $change = static fn (): int => IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($change));

        $this->recordEvents([Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class, SessionRevoked::class, Login::class]);

        $result = $signIn($this->sessions(), $identity);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $result->reason);
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::SIGN_IN, $this->recordedEvent(AuthenticationFailed::class)->flow);
        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, Session::query()->sole()->getRawOriginal('revoked_reason'));
        self::assertTrue(app('auth')->guard('api')->guest());
        self::assertSame([], $limiter->released);
    }

    /**
     * A pending sign-in whose identity is deactivated after its admission is
     * refused the same way: its pending session is revoked and its credential
     * never handed out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInWhoseIdentityIsDeactivatedBeforeItsWriteIsRefused(): void
    {
        $identity = $this->seedIdentity();
        $change   = static fn (): int => IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($change, new Requirement(new RequirementPart)));

        $this->recordEvents([SessionPending::class, SessionRevoked::class]);

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $result->reason);
        self::assertNull($result->credential);
        self::assertSame([], $this->recordedClasses());
        $row = Session::query()->sole();

        self::assertSame([SessionStatus::PENDING, RevocationReason::IDENTITY_DEACTIVATED->value], [$row->getStatus(), $row->getRawOriginal('revoked_reason')]);
    }

    /**
     * A sign-in whose check fails with a database error, outside a transaction,
     * throws it from the call: the session is committed and left unrevoked, but
     * never handed out, so nothing reports it, the guard is not bound to it,
     * and the attempt-limit slots the sign-in took are not given back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInWhoseCheckFailsThrowsWithoutHandingTheSessionOut(): void
    {
        $this->seedIdentity();

        $limiter = new RecordingAttemptLimiter;
        $armed   = false;

        app()->instance(AttemptLimiter::class, $limiter);
        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy(static function () use (&$armed): bool {
            return $armed = true;
        }));

        DB::connection()->beforeExecuting(static function (string $query) use (&$armed): void {
            if (!$armed || !str_starts_with(strtolower($query), 'select') || !str_contains($query, 'integration_identities')) {
                return;
            }

            $armed = false;

            throw new \RuntimeException('identity unreadable');
        });

        $this->recordEvents([SessionCreated::class, SignedIn::class, SessionRevoked::class, Login::class]);

        try {
            $this->sessions()->signIn('password', self::credentials(), self::requestContext());

            self::fail('Expected the check to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('identity unreadable', $exception->getMessage());
        }

        self::assertNull(Session::query()->sole()->getRawOriginal('revoked_at'));
        self::assertSame([], $this->recordedClasses());
        self::assertTrue(app('auth')->guard('api')->guest());
        self::assertNotSame([], $limiter->acquired);
        self::assertSame([], $limiter->released);
    }

    /**
     * Inside a caller's transaction a sign-in whose identity is deactivated
     * after its admission is answered with its session, which the check, at the
     * commit, then revokes and reports as revoked: nothing reports the sign-in,
     * the bind that waited for the commit binds nothing, and the attempt-limit
     * slots the sign-in took stay counted, as they do for a sign-in refused
     * before it answered; one whose session stands gives them back at the
     * commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersTransactionTheSessionIsEndedAtTheCommit(): void
    {
        $identity = $this->seedIdentity();
        $limiter  = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        $sessions = $this->sessions();
        $standing = DB::transaction(static fn (): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext()));

        self::assertTrue($standing->isSignedIn());
        self::assertNotSame([], $limiter->released);

        $limiter->released = [];

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->forgetUser();

        $change = static fn (): int => IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($change));

        $this->recordEvents([Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class, SessionRevoked::class, Login::class]);

        $result = DB::transaction(static fn (): SignInResult => $sessions->signIn('password', self::credentials(), self::requestContext()));

        self::assertTrue($result->isSignedIn());
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(RevocationReason::IDENTITY_DEACTIVATED->value, Session::query()->whereKey($result->session?->record->getKey())->sole()->getRawOriginal('revoked_reason'));
        self::assertTrue($guard->guest());
        self::assertSame([], $limiter->released);
    }

    /**
     * A password change that keeps the session a sign-in wrote earlier in the
     * same transaction, made a second after that sign-in began, leaves the
     * session standing at the commit: the change saw the session and kept it,
     * so the cutoff it moved is no trace of a revocation that could not. Only
     * the identity's other session ends, the sign-in is reported, and the guard
     * stays bound to its session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionAPasswordChangeKeepsInTheSameTransactionStands(): void
    {
        $this->createRecheckedTables();

        [$member] = $this->seedRechecked();

        $sessions = $this->sessions('rechecked');
        $earlier  = self::sessionOf($sessions->signIn('password', self::credentials('rechecked@example.test'), self::requestContext()));
        $later    = $this->now->addSecond();

        $this->recordEvents([SessionCreated::class, SignedIn::class, SessionRevoked::class]);

        $signedIn = DB::transaction(static function () use ($sessions, $member, $later): SignedInSession {
            $signedIn = self::sessionOf($sessions->signIn('password', self::credentials('rechecked@example.test'), self::requestContext()));

            Carbon::setTestNow($later);
            CarbonImmutable::setTestNow($later);

            $sessions->passwordChanged($member, $signedIn->record);

            return $signedIn;
        });

        self::assertSame($later->getTimestamp(), $member->refresh()->getTokensValidAfter()?->getTimestamp());
        self::assertNull(Session::query()->whereKey($signedIn->record->getKey())->sole()->getRawOriginal('revoked_reason'));
        self::assertSame('password_changed', Session::query()->whereKey($earlier->record->getKey())->sole()->getRawOriginal('revoked_reason'));
        self::assertEqualsCanonicalizing([SessionCreated::class, SignedIn::class, SessionRevoked::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($earlier->record->getKey()), $this->recordedEvent(SessionRevoked::class)->context->sessionId);

        $guard = app('auth')->guard('rechecked');

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertSame($signedIn->record->getKey(), $guard->session()?->getSessionIdentifier());
    }

    /**
     * A sign-in given a `SignInContext` built from plain values binds the guard
     * with that context's client: `signIn()` and `start()` alike, their bind's
     * `PrincipalAssigned` and `SessionAuthenticated` carry it, and with a
     * last-use throttle that records every use the session's last use is that
     * client's, not the guard's own request's. A context built from the request
     * being served (`SignInContext::fromRequest()`) binds with that request's
     * client, as any context given does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInGivenAContextBindsWithItsClient(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 0);

        $identity = $this->seedIdentity();
        $context  = new SignInContext(new ClientContext(self::PLAIN_IP, self::PLAIN_AGENT));

        $this->recordEvents([PrincipalAssigned::class, SessionAuthenticated::class]);

        $signedIn = self::sessionOf($this->sessions()->signIn('password', self::credentials(), $context));

        self::assertSame($context->client, $this->recordedEvent(PrincipalAssigned::class)->context->client);
        self::assertSame($context->client, $this->recordedEvent(SessionAuthenticated::class)->context->client);
        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], self::lastUseOf($signedIn));

        $this->recordEvents([PrincipalAssigned::class, SessionAuthenticated::class]);

        $started = self::sessionOf($this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'password', $context));

        self::assertSame($context->client, $this->recordedEvent(SessionAuthenticated::class)->context->client);
        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], self::lastUseOf($started));

        $this->recordEvents([SessionAuthenticated::class]);

        $fromRequest = self::sessionOf($this->sessions()->signIn('password', self::credentials(), self::requestContext()));

        self::assertSame(self::CLIENT_IP, $this->recordedEvent(SessionAuthenticated::class)->context->client->ip);
        self::assertSame([self::CLIENT_IP, self::CLIENT_AGENT], self::lastUseOf($fromRequest));
    }

    /**
     * A cookie application refuses a satisfaction given a client the same-site
     * check refuses, as `cross_site_request`, though the guard's own request is
     * same-site: before the pending session is read, reported with the client
     * given, the session left pending and the proof unstored, so the same
     * satisfaction given the same-site request's client then activates it.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteClients')]
    public function testACookieApplicationRefusesASatisfactionForACrossSiteClientGiven(ClientContext $client): void
    {
        $identity             = $this->seedIdentity();
        [$credential, $proof] = $this->pendingWithProof($identity, self::BROWSER);
        $proofs               = DB::table('authentication_proofs')->count();

        $this->recordEvents([Failed::class, AuthenticationFailed::class, SessionCreated::class, SignedIn::class]);

        $refused = $this->sessionsOn(self::BROWSER, self::SAME_SITE)->satisfy($credential, $proof, $client);

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $refused->reason);
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
        self::assertSame([SessionStatus::PENDING->value], Session::query()->pluck('status')->all());
        self::assertSame($proofs, DB::table('authentication_proofs')->count());
        self::assertTrue(app('auth')->guard(self::BROWSER)->guest());
        self::assertTrue($this->sessionsOn(self::BROWSER, self::SAME_SITE)->satisfy($credential, $proof, self::requestClient())->isSignedIn());
    }

    /**
     * A cookie application's choice given a same-site client activates the
     * session with the cookie though the guard's own request comes from another
     * site; one given a client the same-site check refuses is refused as
     * `cross_site_request` on a same-site request, reported with that client,
     * recording no principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCrossSiteClients')]
    public function testACookieApplicationsChoiceIsJudgedOnTheClientGiven(ClientContext $client): void
    {
        [$credential, $chosen] = $this->pendingChoice(self::BROWSER_CHOOSERS);

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $this->sessionsOn(self::BROWSER_CHOOSERS, self::SAME_SITE)->choose($credential, $chosen, $client)->reason);
        self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
        self::assertSame([null], Session::query()->pluck('principal_id')->all());

        $sessions  = $this->sessionsOn(self::BROWSER_CHOOSERS, ['Origin' => 'https://evil.example.test']);
        $activated = self::sessionOf($sessions->choose($credential, $chosen, self::sameSiteClient()));

        self::assertNotNull($activated->tokens->refreshCookie);
        self::assertSame($chosen->getKey(), $activated->principal->getPrincipalIdentifier());
        self::assertSame(self::PLAIN_IP, Session::query()->sole()->getRawOriginal('last_used_ip'));
    }

    /**
     * A refusal of a pending action given a client, after the same-site check,
     * is reported with that client: a credential that names no pending session,
     * on a cookie application and a body one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedPendingActionIsReportedWithTheClientGiven(): void
    {
        $identity = $this->seedIdentity();

        [, $proof] = $this->pendingWithProof($identity, self::BROWSER);

        foreach ([self::BROWSER => self::sameSiteClient(), 'api' => self::crossSiteClient()] as $guard => $client) {

            $this->recordEvents([AuthenticationFailed::class]);

            self::assertSame(FailureReason::PENDING_INVALID, $this->sessionsOn($guard, [])->satisfy('1.not-a-credential', $proof, $client)->reason);
            self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);

            $this->recordEvents([AuthenticationFailed::class]);

            self::assertSame(FailureReason::PENDING_INVALID, $this->sessionsOn($guard, [])->choose('1.not-a-credential', $identity, $client)->reason);
            self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
        }
    }

    /**
     * A pending credential `PendingCredential::extract()` refused as
     * `pending_invalid`, handed in, is reported as a credential that names no
     * pending session is, with `Failed` and `AuthenticationFailed` carrying the
     * client given and no query, and only after the same-site check, which
     * refuses a cross-site client first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingInvalidHandedInIsReportedAsAnUnknownCredential(): void
    {
        $identity = $this->seedIdentity();

        [, $proof] = $this->pendingWithProof($identity, self::BROWSER);

        $actions = [
            'satisfy' => static fn (SessionService $sessions, ClientContext $client): SignInResult => $sessions->satisfy(FailureReason::PENDING_INVALID, $proof, $client),
            'choose'  => static fn (SessionService $sessions, ClientContext $client): SignInResult => $sessions->choose(FailureReason::PENDING_INVALID, $identity, $client),
        ];

        foreach ($actions as $name => $action) {
            foreach ([self::BROWSER => self::sameSiteClient(), 'api' => self::crossSiteClient()] as $guard => $client) {

                $sessions = $this->sessionsOn($guard, []);

                $this->recordEvents([Failed::class, AuthenticationFailed::class]);

                $queries = 0;

                DB::listen(static function () use (&$queries): void {
                    $queries++;
                });

                self::assertSame(FailureReason::PENDING_INVALID, $action($sessions, $client)->reason, $name);
                self::assertSame(0, $queries, $name);
                self::assertSame([Failed::class, AuthenticationFailed::class], $this->recordedClasses(), $name);
                self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
                self::assertSame(AuthenticationFlow::SIGN_IN, $this->recordedEvent(AuthenticationFailed::class)->flow);
            }

            self::assertSame(FailureReason::CROSS_SITE_REQUEST, $action($this->sessionsOn(self::BROWSER, []), self::crossSiteClient())->reason, $name);
        }
    }

    /**
     * A reason `PendingCredential::extract()` never answers, handed in to a
     * pending action, is the caller's error: it throws before anything is
     * dispatched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherReasonHandedInToAPendingActionIsTheCallersError(): void
    {
        $identity = $this->seedIdentity();

        [, $proof] = $this->pendingWithProof($identity, 'api');

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        $actions = [
            static fn (SessionService $sessions): SignInResult => $sessions->satisfy(FailureReason::SESSION_UNKNOWN, $proof, self::sameSiteClient()),
            static fn (SessionService $sessions): SignInResult => $sessions->choose(FailureReason::PENDING_ACTION_NOT_ALLOWED, $identity, self::sameSiteClient()),
        ];

        foreach ($actions as $action) {
            try {
                $action($this->sessionsOn(self::BROWSER, []));

                self::fail('A pending action took a reason the extraction never answers.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringContainsString('hand in only what `PendingCredential::extract()` answered', $exception->getMessage());
            }
        }

        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A body application is never held to the check, whatever the request
     * carried: its sign-in, start, satisfaction and choice from another site
     * each go ahead, since its tokens travel only in the response body.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABodyApplicationIsNotHeldToTheSameSiteCheck(): void
    {
        $crossSite = ['Origin' => 'https://evil.example.test'];
        $identity  = $this->seedIdentity();

        self::assertNotNull(self::sessionOf($this->sessionsOn('api', $crossSite)->signIn('password', self::credentials(), self::requestContext()))->tokens->refreshToken);
        self::assertTrue($this->sessionsOn('api', $crossSite)->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext())->isSignedIn());

        [$credential, $chosen] = $this->pendingChoice('choosers');

        self::assertTrue($this->sessionsOn('choosers', $crossSite)->choose($credential, $chosen, self::requestClient())->isSignedIn());

        [$credential, $proof] = $this->pendingWithProof($identity, 'api');

        self::assertTrue($this->sessionsOn('api', $crossSite)->satisfy($credential, $proof, self::requestClient())->isSignedIn());
    }

    /**
     * Configure the guards, a guard over identities without sessions, one over
     * members with no default principal, and cookie applications over each.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);
        self::configureRecheckedGuard($config);

        $config->set('auth.providers.plain', ['driver' => 'model', 'model' => NormalizedEmailIdentity::class]);
        $config->set('auth.guards.plain', ['driver' => 'jwt', 'provider' => 'plain', 'application' => ['methods' => ['password']]]);
        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.choosers', ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password', 'sso']]]);

        $cookie = ['transport' => 'cookie', 'cookie' => ['path' => '/auth', 'allowed_origins' => [self::ALLOWED_ORIGIN]]];

        $config->set('auth.guards.' . self::BROWSER, [
            'driver'        => 'jwt',
            'provider'      => 'identities',
            'application'   => ['methods' => ['password', 'sso', 'trusted']],
            'refresh_token' => $cookie,
        ]);
        $config->set('auth.guards.' . self::BROWSER_CHOOSERS, [
            'driver'        => 'jwt',
            'provider'      => 'choosers',
            'application'   => ['methods' => ['password']],
            'refresh_token' => $cookie,
        ]);
        $config->set('database.connections.elsewhere', ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
    }

    /**
     * Sign in with a further factor required of every sign-in, and return the
     * pending session's credential with an accepted further factor's proof
     * bound to it.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  string  $guard
     * @return array{0: string, 1: \SineMacula\Laravel\Authentication\Proofs\ProofResult}
     *
     * @throws \Throwable
     */
    private function pendingWithProof(IntegrationIdentity $identity, string $guard = 'api'): array
    {
        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $result = $this->sessions($guard)->signIn('password', self::credentials(), self::requestContext());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        return [$result->credential->reveal(), self::adapterProof($identity, $guard, $result->pending->id, Purpose::SIGN_IN)];
    }

    /**
     * Sign a member with two memberships in on the guard, from the
     * application's own site, and return the pending session's credential and
     * the second membership to choose.
     *
     * @param  string  $guard
     * @return array{0: string, 1: \Tests\Integration\Fixtures\ChoosingMembership}
     *
     * @throws \Throwable
     */
    private function pendingChoice(string $guard): array
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $tenant = ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);

        ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        $chosen = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $result = $this->sessions($guard)->signIn('password', self::credentials('chooser@example.test'), self::requestContext());

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);

        return [$result->credential->reveal(), $chosen];
    }

    /**
     * Serve a request with the headers from the test client and resolve the
     * named guard's session service afresh for it.
     *
     * @param  string  $guard
     * @param  array<string, string>  $headers
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function sessionsOn(string $guard, array $headers): SessionService
    {
        app()->instance('request', self::requestWith($headers));

        Auth::forgetGuards();

        return self::sessionsOf(app('auth')->guard($guard));
    }

    /**
     * A sign-in request from the test client carrying the headers.
     *
     * @param  array<string, string>  $headers
     * @return \Illuminate\Http\Request
     */
    private static function requestWith(array $headers): Request
    {
        $server = ['REMOTE_ADDR' => self::CLIENT_IP, 'HTTP_USER_AGENT' => self::CLIENT_AGENT];

        foreach ($headers as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }

        return Request::create('/auth/sign-in', 'POST', server: $server);
    }

    /**
     * Create the table of identities without sessions, dropped with the
     * application, and seed one.
     *
     * @return \Tests\Integration\Fixtures\NormalizedEmailIdentity
     */
    private function seedIdentityWithoutSessions(): NormalizedEmailIdentity
    {
        Schema::create('normalized_email_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->nullable()->unique();
            $blueprint->string('name');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::dropIfExists('normalized_email_identities');
        });

        return NormalizedEmailIdentity::query()->create(['email' => 'ada@example.test', 'name' => 'Ada', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
    }

    /**
     * Expect the refusal of an identity class without sessions.
     *
     * @return void
     */
    private function expectRefusalOfIdentitiesWithoutSessions(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('identities that implement %s; %s does not.', HasSessions::class, NormalizedEmailIdentity::class));
    }

    /**
     * Assert a sign-in failed with the reason, returned no session, and wrote
     * no session row.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return void
     */
    private function assertSignInFails(FailureReason $reason, SignInResult $result): void
    {
        self::assertTrue($result->isFailed());
        self::assertFalse($result->isSignedIn());
        self::assertSame(SignInStatus::FAILED, $result->status);
        self::assertSame($reason, $result->reason);
        self::assertNull($result->session);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * Assert the value is the same model as the expected one.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $expected
     * @param  mixed  $actual
     * @return void
     */
    private static function assertSameModel(Model $expected, mixed $actual): void
    {
        self::assertInstanceOf(Model::class, $actual);
        self::assertTrue($expected->is($actual), sprintf('Expected %s %s.', $expected::class, (string) json_encode($expected->getKey())));
    }

    /**
     * The IP address and user agent the session's row records as its last use.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return array{0: mixed, 1: mixed}
     */
    private static function lastUseOf(SignedInSession $session): array
    {
        $row = Session::query()->whereKey($session->record->getSessionIdentifier())->sole();

        return [$row->getRawOriginal('last_used_ip'), $row->getRawOriginal('last_used_user_agent')];
    }

    /**
     * The session a sign-in started, asserting it started one.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private static function sessionOf(SignInResult $result): SignedInSession
    {
        self::assertNotNull($result->session, 'Expected the sign-in to start a session; it failed with ' . $result->reason?->value);

        return $result->session;
    }

    /**
     * Bind a permissive application policy mock with the guard's own lifetimes,
     * whose expectations a test can override.
     *
     * @return \Mockery\MockInterface
     */
    private function policy(): MockInterface
    {
        $policy = $this->bindMock(ApplicationPolicy::class);
        $policy->shouldReceive('allowsMethod')->byDefault()->andReturnTrue();
        $policy->shouldReceive('admitIdentifier')->byDefault()->andReturnNull();
        $policy->shouldReceive('lifetimes')
            ->byDefault()
            ->andReturnUsing(static fn (string $guard): TokenLifetimes => app(JwtTokenServiceFactory::class)->forGuard($guard)->lifetimes());

        return $policy;
    }

    /**
     * Run the sign-in, expecting a listener to throw, and return the
     * exception's message.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Sessions\SignInResult  $signIn
     * @return string
     */
    private static function failureOf(\Closure $signIn): string
    {
        try {
            $signIn();
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
    }

    /**
     * Bind a mock of the contract in the container.
     *
     * @param  class-string  $contract
     * @return \Mockery\MockInterface
     */
    private function bindMock(string $contract): MockInterface
    {
        $mock = \Mockery::mock($contract);

        assert($this->app !== null);

        $this->app->instance($contract, $mock);

        return $mock;
    }

    /**
     * Register a `trusted` sign-in method that vouches for the given identity
     * (or for no one, or refuses with the given reason), naming the given
     * identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null  $identity
     * @param  ?string  $identifier
     * @return void
     */
    private function registerTrustedMethod(FailureReason|Identity|null $identity, ?string $identifier = null): void
    {
        $method = new class ($identity, $identifier) implements SignInMethod {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|null  $identity
             * @param  ?string  $identifier
             */
            public function __construct(

                /** Identity the method vouches for, or the reason it refuses with. */
                private readonly FailureReason|Identity|null $identity,

                /** Identifier the method names. */
                private readonly ?string $identifier,
            ) {}

            /**
             * No identifier type.
             *
             * @param  string  $guard
             * @return ?string
             */
            #[\Override]
            public function identifierType(string $guard): ?string
            {
                unset($guard);

                return null;
            }

            /**
             * The configured identifier.
             *
             * @param  string  $guard
             * @param  array<array-key, mixed>  $input
             * @return ?string
             */
            #[\Override]
            public function identifier(string $guard, #[\SensitiveParameter] array $input): ?string
            {
                unset($guard, $input);

                return $this->identifier;
            }

            /**
             * The challenge the input names, when it names one.
             *
             * @param  array<array-key, mixed>  $input
             * @return ?string
             */
            #[\Override]
            public function challenge(#[\SensitiveParameter] array $input): ?string
            {
                return is_string($input['challenge'] ?? null) ? $input['challenge'] : null;
            }

            /**
             * Vouch for the configured identity, or refuse as configured.
             *
             * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
             * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Proofs\FirstFactor
             */
            #[\Override]
            public function authenticate(SignInRequest $request): FailureReason|FirstFactor
            {
                return $this->identity instanceof Identity
                    ? new FirstFactor($this->identity, new Channel(ChannelKind::UNKNOWN))
                    : $this->identity ?? FailureReason::INVALID_CREDENTIALS;
            }
        };

        $manager = app(SignInMethodManager::class);

        $manager->forgetDrivers();
        $manager->extend('trusted', fn (): SignInMethod => $method);
    }

    /**
     * The identity's hash as the database now holds it.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return mixed
     */
    private function storedHash(IntegrationIdentity $identity): mixed
    {
        return IntegrationIdentity::query()->whereKey($identity->getKey())->value('password');
    }
}
