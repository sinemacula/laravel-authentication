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
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\Fixtures\Sessions\RefusalIgnoringSignIn;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\NormalisedEmailIdentity;
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
#[CoversClass(SignInResult::class)]
final class SessionServiceTest extends TestCase
{
    use InteractsWithSessions;

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
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A password sign-in starts a session on a new device: the result carries
     * the identity, principal, device, method and first pair; the device
     * records who, as whom, through which guard and method, from which client,
     * the sign-in as its last use, the digest of the refresh token's rotation
     * id, and the guard's deadlines; and the guard is bound to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInStartsASessionOnANewDevice(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        $result = $guard->sessions()->signIn('password', self::credentials(), SignInContext::fromRequest(app('request'), 'Work laptop', 'macOS'));

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
        self::assertTrue($session->deviceCreated);

        $device = Device::query()->whereKey($session->device->getKey())->firstOrFail();
        $claims = Auth::manager()->jwt('api')->parse($session->tokens->refreshToken);

        self::assertNotNull($claims);
        self::assertSame($device->getKey(), $claims['did']);
        self::assertSame(IntegrationIdentity::class, $device->authenticatable_type);
        self::assertSame((string) $identity->id, $device->authenticatable_id);
        self::assertSame(IntegrationIdentity::class, $device->principal_type);
        self::assertSame((string) $identity->id, $device->principal_id);
        self::assertSame('api', $device->getGuard());
        self::assertSame('password', $device->getSignInMethod());
        self::assertSame('Work laptop', $device->client_name);
        self::assertSame('macOS', $device->platform);
        self::assertSame(self::CLIENT_IP, $device->created_ip);
        self::assertSame(self::CLIENT_AGENT, $device->created_user_agent);
        self::assertSame(self::CLIENT_IP, $device->last_used_ip);
        self::assertSame(self::CLIENT_AGENT, $device->last_used_user_agent);
        self::assertSame($this->now->getTimestamp(), $device->getLastUsedAt()?->getTimestamp());
        self::assertIsString($claims['jti']);
        self::assertTrue(RefreshTokenHasher::verify($claims['jti'], (string) $device->getRefreshKey()));
        self::assertNull($device->getPreviousRefreshKey());
        self::assertNull($device->getRefreshRotatedAt());
        self::assertSame($this->now->addDays(30)->getTimestamp(), $device->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addDays(180)->getTimestamp(), $device->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertNull($device->getRevokedAt());

        self::assertSame($session->identity, $guard->user());
        self::assertSame($session->principal, $guard->principal());
        self::assertSame($session->device, $guard->device());
    }

    /**
     * A successful sign-in announces itself in a fixed order: `Attempting`,
     * then `DeviceCreated` and `SignedIn`, reported before the bind, then the
     * bind events, each lifecycle event carrying the sign-in's context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInDispatchesDeviceCreatedAndSignedInThenTheBindEvents(): void
    {
        $this->seedIdentity();

        $this->recordEvents([
            Attempting::class,
            Validated::class,
            Login::class,
            Authenticated::class,
            PrincipalAssigned::class,
            DeviceAuthenticated::class,
            DeviceCreated::class,
            SignedIn::class,
            Failed::class,
            AuthenticationFailed::class,
        ]);

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertSame(
            [Attempting::class, DeviceCreated::class, SignedIn::class, Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class],
            $this->recordedClasses(),
        );

        $session  = $result->session;
        $created  = $this->recordedEvent(DeviceCreated::class);
        $signedIn = $this->recordedEvent(SignedIn::class);

        self::assertNotNull($session);

        foreach ([$created, $signedIn] as $event) {
            self::assertSame('api', $event->context->guard);
            self::assertSame($session->identity, $event->context->identity);
            self::assertSame($session->principal, $event->context->principal);
            self::assertNull($event->context->tenant);
            self::assertSame($session->device, $event->context->device);
            self::assertSame('password', $event->context->method);
            self::assertSame(self::CLIENT_IP, $event->context->client->ip);
            self::assertSame(self::CLIENT_AGENT, $event->context->client->userAgent);
        }

        self::assertTrue($signedIn->deviceCreated);
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

        $result = $this->sessions()->signIn('password', $input);

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
     * verified the input and that was admitted: a wrong password waits it out.
     * What follows admission (here a required factor) runs after the timebox,
     * once the input is known to be right.
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

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'])->isFailed());

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->andReturnTrue();

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->requiresFactor());
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
            $this->sessions()->signIn('carrier-pigeon', []);
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

        $audience = $this->audience();
        $audience->shouldReceive('allowsMethod')->once()->with('api', 'password')->andReturnFalse();

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldNotReceive('acquire');

        $this->assertSignInFails(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->signIn('password', self::credentials()));
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

        $limited = $this->sessions()->signIn('password', ['email' => ' ADA@example.test ', 'password' => self::PASSWORD]);

        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(42, $limited->retryAfter);

        $wrong = $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong']);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $wrong->reason);
        self::assertCount(0, $released);

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
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
        self::assertSame(1, Device::query()->count());
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

        $this->assertSignInFails(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong']));
        $this->assertSignInFails(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', self::credentials('nobody@example.test')));
        $this->assertSignInFails(FailureReason::IDENTITY_INACTIVE, $this->sessions()->signIn('password', self::credentials('inactive@example.test')));
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

        $default = $this->sessions('members')->signIn('password', self::credentials('member@example.test'));

        self::assertSameModel($membership, self::sessionOf($default)->principal);

        $context = new SignInContext(new ClientContext(null, null), principal: $membership);
        $pinned  = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context);

        $pinnedSession = self::sessionOf($pinned);

        self::assertSameModel($membership, $pinnedSession->principal);
        self::assertSame(IdentifierCoercion::stringify($membership->getKey()), Device::query()->whereKey($pinnedSession->device->getKey())->firstOrFail()->principal_id);

        $this->recordEvents([AuthenticationFailed::class]);

        $mismatch = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), new SignInContext(new ClientContext(null, null), principal: $foreign));

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $mismatch->reason);
        self::assertNull($this->recordedEvent(AuthenticationFailed::class)->context->principal);

        $membership->delete();
        $foreign->delete();

        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->reason);
    }

    /**
     * A membership acting within an inactive tenant fails, and the failure
     * reports the membership it resolved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalInAnInactiveTenantFails(): void
    {
        $tenant = ActivatableTenant::query()->create(['name' => 'Closed', 'is_active' => false]);

        [, $membership] = $this->seedMember(tenant: $tenant);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->assertSignInFails(FailureReason::TENANT_INACTIVE, $this->sessions('members')->signIn('password', self::credentials('member@example.test')));
        self::assertSameModel($membership, $this->recordedEvent(AuthenticationFailed::class)->context->principal);
    }

    /**
     * The audience policy admits the identity as the principal for the method's
     * identifier type; its refusal fails the sign-in with its reason and the
     * whole context, tenant included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAudiencePolicysRefusalFailsTheSignIn(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $audience = $this->audience();
        $audience->shouldReceive('admit')
            ->once()
            ->with('members', \Mockery::on(static fn (Identity $identity): bool => $identity->getAuthIdentifier() === $member->getKey()), \Mockery::any(), 'email')
            ->andReturn(FailureReason::PRINCIPAL_INELIGIBLE);

        $this->recordEvents([Failed::class, AuthenticationFailed::class]);

        $this->assertSignInFails(FailureReason::PRINCIPAL_INELIGIBLE, $this->sessions('members')->signIn('password', self::credentials('member@example.test')));

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSameModel($member, $failed->context->identity);
        self::assertSameModel($membership, $failed->context->principal);
        self::assertSameModel($tenant, $failed->context->tenant);
        self::assertSame('password', $failed->context->method);
        self::assertSame('member@example.test', $failed->identifier);
        self::assertSame($failed->context->identity, $this->recordedEvent(Failed::class)->user);
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

        $result = $this->sessions()->signIn('password', self::credentials());

        $this->assertSignInFails(FailureReason::INVALID_CREDENTIALS, $result);
        self::assertNull($result->retryAfter);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $failed->reason);
        self::assertSame(90, $failed->retryAfter);
        self::assertNull($failed->context->identity);
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

        $this->recordEvents([AuthenticationFailed::class, SignedIn::class, AdditionalFactorRequired::class]);

        $result = $this->sessions()->signIn('trusted', self::credentials());

        $this->assertSignInFails(FailureReason::INVALID_CREDENTIALS, $result);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(90, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * The additional-factor policy is asked about every admitted sign-in, with
     * the client's description and no proven device; a sign-in it asks a factor
     * of starts no session: it hands out a pending sign-in for the identity and
     * principal, which does not fail the sign-in and keeps every slot the
     * sign-in took, the account's included, recording their windows.
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
        $factors->shouldReceive('requiresAdditionalFactor')->once()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): bool {
            $asked = $context;

            return true;
        });

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->andReturnUsing(static function (AttemptSubject $subject): AttemptReservation {
            $slot = $subject->account === null ? 'sign-in' : 'account';

            return new AttemptReservation($subject, null, [$slot => '2026-04-06 12:05:00']);
        });
        $limiter->shouldReceive('release')->never();

        $this->recordEvents([Failed::class, AuthenticationFailed::class, DeviceCreated::class, SignedIn::class]);

        $guard   = $this->freshGuard();
        $context = SignInContext::fromRequest(app('request'), 'Phone', 'iOS');
        $result  = $guard->sessions()->signIn('password', self::credentials(), $context);

        self::assertTrue($result->requiresFactor());
        self::assertFalse($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertSame(SignInStatus::FACTOR_REQUIRED, $result->status);
        self::assertNull($result->session);
        self::assertNull($result->reason);
        self::assertNotNull($result->pending);
        self::assertSameModel($identity, $result->pending->identity);
        self::assertSame('password', $result->pending->method);
        self::assertSame('api', $result->pending->guard);
        self::assertSame([['sign-in' => '2026-04-06 12:05:00'], ['account' => '2026-04-06 12:05:00']], PendingSignIn::query()->sole()->attempt_windows);
        self::assertSame(0, Device::query()->count());
        self::assertSame([], $this->recordedClasses());
        self::assertFalse($guard->hasUser());

        self::assertInstanceOf(AdditionalFactorContext::class, $asked);
        self::assertSame('api', $asked->guard);
        self::assertSameModel($identity, $asked->identity);
        self::assertSame($asked->identity, $asked->principal);
        self::assertNull($asked->tenant);
        self::assertSame('password', $asked->method);
        self::assertSame($context->client, $asked->client);
        self::assertSame('Phone', $asked->clientName);
        self::assertSame('iOS', $asked->platform);
        self::assertNull($asked->provenDevice);
    }

    /**
     * A sign-in acting within a tenant carries that tenant on: the factor
     * policy is told of it, and so are `DeviceCreated` and `SignedIn` when the
     * session starts (the first sign-in), and the pending sign-in and
     * `AdditionalFactorRequired` when a further factor is required (the
     * second).
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
        $factors->shouldReceive('requiresAdditionalFactor')->twice()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): bool {
            $asked[] = $context->tenant;

            return count($asked) === 2;
        });

        $this->recordEvents([DeviceCreated::class, SignedIn::class, AdditionalFactorRequired::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);
        self::assertSameModel($membership, $session->principal);
        self::assertSameModel($tenant, $this->recordedEvent(DeviceCreated::class)->context->tenant);
        self::assertSameModel($tenant, $this->recordedEvent(SignedIn::class)->context->tenant);

        $pending = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->pending;

        self::assertNotNull($pending);
        self::assertSameModel($tenant, $pending->tenant);
        self::assertSameModel($tenant, $this->recordedEvent(AdditionalFactorRequired::class)->context->tenant);
        self::assertCount(2, $asked);
        self::assertSameModel($tenant, $asked[0]);
        self::assertSameModel($tenant, $asked[1]);
    }

    /**
     * The device's deadlines follow the lifetimes the audience policy gives the
     * principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeadlinesFollowTheAudiencePolicysLifetimes(): void
    {
        $this->seedIdentity();

        $audience = $this->audience();
        $audience->shouldReceive('lifetimes')->once()->with('api', \Mockery::type(IntegrationIdentity::class))->andReturn(new TokenLifetimes(5, 60, 120, 30));

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);
        self::assertSame($this->now->addHour()->getTimestamp(), $session->device->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addHours(2)->getTimestamp(), $session->device->getAbsoluteExpiresAt()?->getTimestamp());
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

        self::assertTrue($this->sessions()->signIn('trusted', [])->isSignedIn());
        self::assertSame($outdated, $this->storedHash($identity));

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
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

        self::assertTrue($this->sessions()->signIn('trusted', [])->isSignedIn());
        self::assertSame(['identifier' => 'ada'], $this->recordedEvent(Attempting::class)->credentials);

        $this->registerTrustedMethod(null);
        $this->recordEvents([Attempting::class, AuthenticationFailed::class]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('trusted', [])->reason);
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
        $this->registerTrustedMethod(FailureReason::DEVICE_REVOKED);
        $this->recordEvents([AuthenticationFailed::class]);

        try {
            $this->sessions()->signIn('trusted', []);
            self::fail('Expected a LogicException.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('`device_revoked`', $exception->getMessage());
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

        $this->recordEvents([Attempting::class, Validated::class, DeviceCreated::class, SignedIn::class]);

        $result = $this->sessions()->start($stale, null, 'sso');

        self::assertTrue($result->isSignedIn());
        $session = self::sessionOf($result);

        self::assertNotSame($stale, $session->identity);
        self::assertSameModel($identity, $session->identity);
        self::assertSame('sso', $session->device->getSignInMethod());
        self::assertSame([DeviceCreated::class, SignedIn::class, Validated::class], $this->recordedClasses());
        self::assertSame('sso', $this->recordedEvent(SignedIn::class)->context->method);
    }

    /**
     * `start()` refuses an identity the guard's provider does not return as
     * that very identity and a method the guard does not allow, and hands out a
     * pending sign-in when the factor policy asks a factor of it, so a sign-in
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

        $this->assertSignInFails(FailureReason::IDENTITY_UNKNOWN, $this->sessions()->start($unsaved, null, 'sso'));
        self::assertSame($unsaved, $this->recordedEvent(Failed::class)->user);
        self::assertSame([], $this->recordedEvent(Failed::class)->credentials);

        $audience = $this->audience();
        $audience->shouldReceive('allowsMethod')->with('api', 'sso')->andReturnFalse();

        $this->assertSignInFails(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->start($identity, null, 'sso'));

        $audience->shouldReceive('allowsMethod')->with('api', 'otp')->andReturnTrue();

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->once()->andReturnTrue();

        $pending = $this->sessions()->start($identity, null, 'otp');

        self::assertTrue($pending->requiresFactor());
        self::assertSame('otp', $pending->pending?->method);
        self::assertSame(0, Device::query()->count());
    }

    /**
     * Rows of `[credential kind]`: what an audience may list that is not a
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
     * guard whose audience lists it: no session is recorded under it, so none
     * passes for a machine credential.
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

        config()->set('auth.guards.api.audience', ['methods' => ['password', $kind]]);

        try {
            $this->sessions()->start($identity, null, $kind);

            self::fail('A session was started under a machine credential kind.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("[{$kind}] names a machine credential, not a sign-in method; no session can be started with it.", $exception->getMessage());
        }

        self::assertSame(0, Device::query()->count());
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

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $this->sessions()->start($member, null, 'sso')->reason);
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

        self::assertSameModel($membership, self::sessionOf($this->sessions('members')->start($member, $membership, 'sso'))->principal);
        self::assertSameModel($membership, self::sessionOf($this->sessions('members')->start($member, null, 'sso', $context))->principal);
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $this->sessions('members')->start($member, $foreign, 'sso')->reason);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Name the principal to start a session as either as the argument or on the context, not both.');

        $this->sessions('members')->start($member, $membership, 'sso', $context);
    }

    /**
     * Signing in an identity that does not own devices fails as the
     * misconfiguration it is, naming the identity class, and writes no device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInRefusesAnIdentityWithoutDevices(): void
    {
        $this->seedIdentityWithoutDevices();

        $this->expectRefusalOfIdentitiesWithoutDevices();

        try {
            $this->sessions('plain')->signIn('password', self::credentials());
        } finally {
            self::assertSame(0, Device::query()->count());
        }
    }

    /**
     * Starting a session for an identity that does not own devices fails the
     * same way.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testStartRefusesAnIdentityWithoutDevices(): void
    {
        $identity = $this->seedIdentityWithoutDevices();

        $this->expectRefusalOfIdentitiesWithoutDevices();

        $this->sessions('plain')->start($identity, null, 'password');
    }

    /**
     * Completing a pending sign-in of an identity that does not own devices
     * fails the same way before anything is written, so the pending sign-in is
     * not used up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCompleteRefusesAnIdentityWithoutDevicesAndKeepsThePendingSignIn(): void
    {
        $identity = $this->seedIdentityWithoutDevices();
        $pending  = (new PendingSignIns(app(ConfigRepository::class)))->issue(
            'plain',
            new AdmittedSignIn($identity, $identity, null),
            'password',
            'email',
            new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT)),
            CarbonImmutable::now()->startOfSecond(),
        );

        $this->expectRefusalOfIdentitiesWithoutDevices();

        try {
            $this->sessions('plain')->complete($pending->token);
        } finally {
            self::assertSame(1, PendingSignIn::query()->count());
            self::assertSame(0, Device::query()->count());
        }
    }

    /**
     * Whatever limiter is bound, one that throws when a completed sign-in gives
     * its slots back has its error reported, not thrown: the completion returns
     * its session, the guard is bound, and the slots after the one that failed
     * are not given back either.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCompleteReportsALimiterThatCannotGiveTheSlotsBack(): void
    {
        $identity = $this->seedIdentity();
        $pending  = (new PendingSignIns(app(ConfigRepository::class)))->issue(
            'api',
            new AdmittedSignIn($identity, $identity, null),
            'password',
            'email',
            new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT)),
            CarbonImmutable::now()->startOfSecond(),
            [['identifier' => 'window'], ['account' => 'window']],
        );

        $failure    = new \RuntimeException('The counters are unreachable.');
        $exceptions = Exceptions::fake([\RuntimeException::class]);
        $limiter    = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('release')->once()->andThrow($failure);

        $result = Auth::sessions('api')->complete($pending->token);

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
            'Validated'           => [Validated::class],
            'Login'               => [Login::class],
            'Authenticated'       => [Authenticated::class],
            'PrincipalAssigned'   => [PrincipalAssigned::class],
            'DeviceAuthenticated' => [DeviceAuthenticated::class],
        ];
    }

    /**
     * A listener that throws on any bind event fails the sign-in after its
     * session committed, but cannot withhold the session's report:
     * `DeviceCreated` and `SignedIn` were dispatched, once, before the bind,
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

        $this->recordEvents([DeviceCreated::class, SignedIn::class, $bindEvent]);

        Event::listen($bindEvent, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        self::assertSame('listener failed', self::failureOf(fn (): SignInResult => $this->sessions()->signIn('password', self::credentials())));
        self::assertSame([DeviceCreated::class, SignedIn::class, $bindEvent], $this->recordedClasses());
        self::assertSame(1, Device::query()->count());
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

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        self::assertSame('listener failed', self::failureOf(fn (): SignInResult => $this->sessions()->start($identity, null, 'sso')));
        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame('sso', $this->recordedEvent(SignedIn::class)->context->method);
    }

    /**
     * A completion whose bind listener throws is reported, and still gives the
     * slots its sign-in took back: both were scheduled before the bind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionWhoseBindListenerThrowsIsStillReportedAndGivesItsSlotsBack(): void
    {
        $identity = $this->seedIdentity();
        $pending  = (new PendingSignIns(app(ConfigRepository::class)))->issue(
            'api',
            new AdmittedSignIn($identity, $identity, null),
            'password',
            'email',
            new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT)),
            CarbonImmutable::now()->startOfSecond(),
            [['identifier' => 'window'], ['account' => 'window']],
        );

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('release')->twice();

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        Event::listen(Authenticated::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        self::assertSame('listener failed', self::failureOf(fn (): SignInResult => $this->sessions()->complete($pending->token)));
        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * Inside a caller's transaction, a completion whose bind listener throws
     * reports the session and gives its sign-in's slots back only once the
     * caller commits. A rollback withdraws both with the session and restores
     * the pending sign-in, which can then be completed again; the slots are
     * given back once, for the completion that committed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionWhoseBindListenerThrowsFollowsTheCallersTransaction(): void
    {
        $identity = $this->seedIdentity();
        $pending  = (new PendingSignIns(app(ConfigRepository::class)))->issue(
            'api',
            new AdmittedSignIn($identity, $identity, null),
            'password',
            'email',
            new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT)),
            CarbonImmutable::now()->startOfSecond(),
            [['identifier' => 'window'], ['account' => 'window']],
        );

        $limiter = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        Event::listen(Authenticated::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        $complete = fn (): SignInResult => $this->sessions()->complete($pending->token);

        DB::beginTransaction();

        self::assertSame('listener failed', self::failureOf($complete));

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertCount(0, $limiter->released);
        self::assertSame(0, Device::query()->count());
        self::assertSame(1, PendingSignIn::query()->count());

        DB::beginTransaction();

        self::assertSame('listener failed', self::failureOf($complete));
        self::assertSame([], $this->recordedClasses());
        self::assertCount(0, $limiter->released);

        DB::commit();

        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertCount(2, $limiter->released);
        self::assertSame(1, Device::query()->count());
        self::assertSame(0, PendingSignIn::query()->count());
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

        self::assertSame('listener failed', self::failureOf(static fn (): SignInResult => $guard->sessions()->signIn('password', self::credentials())));
        self::assertSame([], $this->recordedClasses());
        self::assertFalse($guard->hasUser());
        self::assertSame(1, Device::query()->count());
    }

    /**
     * Configure the guards, and a guard over identities without devices.
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

        $config->set('auth.providers.plain', ['driver' => 'model', 'model' => NormalisedEmailIdentity::class]);
        $config->set('auth.guards.plain', ['driver' => 'jwt', 'provider' => 'plain']);
    }

    /**
     * Create the table of identities without devices, dropped with the
     * application, and seed one.
     *
     * @return \Tests\Integration\Fixtures\NormalisedEmailIdentity
     */
    private function seedIdentityWithoutDevices(): NormalisedEmailIdentity
    {
        Schema::create('normalised_email_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->nullable()->unique();
            $blueprint->string('name');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->beforeApplicationDestroyed(static function (): void {
            Schema::dropIfExists('normalised_email_identities');
        });

        return NormalisedEmailIdentity::query()->create(['email' => 'ada@example.test', 'name' => 'Ada', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
    }

    /**
     * Expect the refusal of an identity class without devices.
     *
     * @return void
     */
    private function expectRefusalOfIdentitiesWithoutDevices(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf('identities that implement %s; %s does not.', HasDevices::class, NormalisedEmailIdentity::class));
    }

    /**
     * Assert a sign-in failed with the reason, started no session, and created
     * no device.
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
        self::assertSame(0, Device::query()->count());
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
     * Bind a permissive audience policy mock with the guard's own lifetimes,
     * whose expectations a test can override.
     *
     * @return \Mockery\MockInterface
     */
    private function audience(): MockInterface
    {
        $audience = $this->bindMock(AudiencePolicy::class);
        $audience->shouldReceive('allowsMethod')->byDefault()->andReturnTrue();
        $audience->shouldReceive('admitIdentifier')->byDefault()->andReturnNull();
        $audience->shouldReceive('admit')->byDefault()->andReturnNull();
        $audience->shouldReceive('lifetimes')
            ->byDefault()
            ->andReturnUsing(static fn (string $guard): TokenLifetimes => app(JwtTokenServiceFactory::class)->forGuard($guard)->lifetimes());

        return $audience;
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
             * Vouch for the configured identity, or refuse as configured.
             *
             * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
             * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
             */
            #[\Override]
            public function authenticate(SignInRequest $request): FailureReason|Identity
            {
                return $this->identity ?? FailureReason::INVALID_CREDENTIALS;
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
