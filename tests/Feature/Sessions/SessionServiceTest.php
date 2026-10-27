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
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Timebox;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Enums\SignInStatus;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
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
     * A successful sign-in announces itself in a fixed order: `Attempting`, the
     * bind events, then `DeviceCreated` and `SignedIn`, each carrying the
     * sign-in's context.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInDispatchesTheBindEventsThenDeviceCreatedThenSignedIn(): void
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
            SignInFailed::class,
        ]);

        $result = $this->sessions()->signIn('password', self::credentials());

        self::assertSame(
            [Attempting::class, Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class, DeviceCreated::class, SignedIn::class],
            $this->recordedClasses(),
        );

        $session  = $result->session;
        $created  = $this->recordedEvent(DeviceCreated::class);
        $signedIn = $this->recordedEvent(SignedIn::class);

        self::assertNotNull($session);

        foreach ([$created, $signedIn] as $event) {
            self::assertSame('api', $event->guard);
            self::assertSame($session->identity, $event->identity);
            self::assertSame($session->principal, $event->principal);
            self::assertNull($event->tenant);
            self::assertSame($session->device, $event->device);
            self::assertSame('password', $event->method);
            self::assertSame(self::CLIENT_IP, $event->client->ip);
            self::assertSame(self::CLIENT_AGENT, $event->client->userAgent);
        }

        self::assertTrue($signedIn->deviceCreated);
    }

    /**
     * The events never see the input: `Attempting` and `Failed` carry only the
     * identifier the method names, and `SignInFailed` no secret at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEventsCarryOnlyTheIdentifierNeverTheInput(): void
    {
        $this->seedIdentity();

        $this->recordEvents([Attempting::class, Failed::class, SignInFailed::class]);

        $input = ['email' => 'ada@example.test', 'password' => 'not-the-password', 'otp' => '123456', 'remember' => 'yes'];

        $result = $this->sessions()->signIn('password', $input);

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $result->reason);
        self::assertSame(['email' => 'ada@example.test'], $this->recordedEvent(Attempting::class)->credentials);
        self::assertFalse($this->recordedEvent(Attempting::class)->remember);
        self::assertSame(['email' => 'ada@example.test'], $this->recordedEvent(Failed::class)->credentials);
        self::assertNull($this->recordedEvent(Failed::class)->user);

        $failed = serialize($this->recordedEvent(SignInFailed::class));

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
        $this->recordEvents([Attempting::class, Failed::class, SignInFailed::class]);

        try {
            $this->sessions()->signIn('carrier-pigeon', []);
            self::fail('Expected an unknown method to throw.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Driver [carrier-pigeon] not supported.', $exception->getMessage());
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

        $this->assertSignInFails(SignInFailureReason::METHOD_NOT_ALLOWED, $this->sessions()->signIn('password', self::credentials()));
    }

    /**
     * An attempt over its limit fails with the wait, without checking the
     * input; one under it takes a slot for the identifier as given, its type
     * and the client's IP address, then one on the account its password is
     * checked against, and a success gives both back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAttemptLimitsAreReservedAndGivenBackOnlyOnSuccess(): void
    {
        $this->seedIdentity();

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

        self::assertSame(SignInFailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(42, $limited->retryAfter);

        $wrong = $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong']);

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $wrong->reason);
        self::assertCount(0, $released);

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
        self::assertCount(2, $released);

        [$limitedSubject, , $wrongAccount, $successSubject, $successAccount] = $subjects->getArrayCopy();
        [$accountRelease, $release]                                          = $released->getArrayCopy();

        self::assertSame($successAccount, $accountRelease->subject);
        self::assertSame($successSubject, $release->subject);
        self::assertSame(IntegrationIdentity::class . "\x001", $wrongAccount->account);
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

        $this->assertSignInFails(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong']));
        $this->assertSignInFails(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', self::credentials('nobody@example.test')));
        $this->assertSignInFails(SignInFailureReason::IDENTITY_INACTIVE, $this->sessions()->signIn('password', self::credentials('inactive@example.test')));
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

        $this->recordEvents([SignInFailed::class]);

        $mismatch = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), new SignInContext(new ClientContext(null, null), principal: $foreign));

        self::assertSame(SignInFailureReason::PRINCIPAL_MISMATCH, $mismatch->reason);
        self::assertNull($this->recordedEvent(SignInFailed::class)->principal);

        $membership->delete();
        $foreign->delete();

        self::assertSame(SignInFailureReason::PRINCIPAL_UNRESOLVED, $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->reason);
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

        $this->recordEvents([SignInFailed::class]);

        $this->assertSignInFails(SignInFailureReason::TENANT_INACTIVE, $this->sessions('members')->signIn('password', self::credentials('member@example.test')));
        self::assertSameModel($membership, $this->recordedEvent(SignInFailed::class)->principal);
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
            ->andReturn(SignInFailureReason::PRINCIPAL_INELIGIBLE);

        $this->recordEvents([Failed::class, SignInFailed::class]);

        $this->assertSignInFails(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->sessions('members')->signIn('password', self::credentials('member@example.test')));

        $failed = $this->recordedEvent(SignInFailed::class);

        self::assertSameModel($member, $failed->identity);
        self::assertSameModel($membership, $failed->principal);
        self::assertSameModel($tenant, $failed->tenant);
        self::assertSame('password', $failed->method);
        self::assertSame('member@example.test', $failed->identifier);
        self::assertSame($failed->identity, $this->recordedEvent(Failed::class)->user);
    }

    /**
     * The additional-factor policy is asked about every admitted sign-in, with
     * the client's description and no proven device; a sign-in it asks a factor
     * of starts no session: it hands out a pending sign-in for the identity and
     * principal, which does not fail the sign-in and gives its attempt slot
     * back.
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

        $released = 0;

        $limiter = $this->bindMock(AttemptLimiter::class);
        $limiter->shouldReceive('acquire')->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, null));
        $limiter->shouldReceive('release')->twice()->andReturnUsing(static function (AttemptReservation $reservation) use (&$released): void {
            $released += $reservation->subject->account === null ? 1 : 0;
        });

        $this->recordEvents([Failed::class, SignInFailed::class, DeviceCreated::class, SignedIn::class]);

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
        self::assertSame(1, $released);
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
        $this->recordEvents([Attempting::class, SignInFailed::class]);

        self::assertTrue($this->sessions()->signIn('trusted', [])->isSignedIn());
        self::assertSame(['identifier' => 'ada'], $this->recordedEvent(Attempting::class)->credentials);

        $this->registerTrustedMethod(null);
        $this->recordEvents([Attempting::class, SignInFailed::class]);

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('trusted', [])->reason);
        self::assertSame([], $this->recordedEvent(Attempting::class)->credentials);
        self::assertNull($this->recordedEvent(SignInFailed::class)->identifier);
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
        self::assertSame([Validated::class, DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame('sso', $this->recordedEvent(SignedIn::class)->method);
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

        $this->recordEvents([Failed::class, SignInFailed::class]);

        $this->assertSignInFails(SignInFailureReason::IDENTITY_UNKNOWN, $this->sessions()->start($unsaved, null, 'sso'));
        self::assertSame($unsaved, $this->recordedEvent(Failed::class)->user);
        self::assertSame([], $this->recordedEvent(Failed::class)->credentials);

        $audience = $this->audience();
        $audience->shouldReceive('allowsMethod')->with('api', 'sso')->andReturnFalse();

        $this->assertSignInFails(SignInFailureReason::METHOD_NOT_ALLOWED, $this->sessions()->start($identity, null, 'sso'));

        $audience->shouldReceive('allowsMethod')->with('api', 'otp')->andReturnTrue();

        $factors = $this->bindMock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->once()->andReturnTrue();

        $pending = $this->sessions()->start($identity, null, 'otp');

        self::assertTrue($pending->requiresFactor());
        self::assertSame('otp', $pending->pending?->method);
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

        self::assertSame(SignInFailureReason::IDENTITY_UNKNOWN, $this->sessions()->start($member, null, 'sso')->reason);
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
        self::assertSame(SignInFailureReason::PRINCIPAL_MISMATCH, $this->sessions('members')->start($member, $foreign, 'sso')->reason);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Name the principal to start a session as either as the argument or on the context, not both.');

        $this->sessions('members')->start($member, $membership, 'sso', $context);
    }

    /**
     * Configure the guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Assert a sign-in failed with the reason, started no session, and created
     * no device.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return void
     */
    private function assertSignInFails(SignInFailureReason $reason, SignInResult $result): void
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
        $audience->shouldReceive('admit')->byDefault()->andReturnNull();
        $audience->shouldReceive('lifetimes')
            ->byDefault()
            ->andReturnUsing(static fn (string $guard): TokenLifetimes => app(JwtTokenServiceFactory::class)->forGuard($guard)->lifetimes());

        return $audience;
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
     * (or for no one), naming the given identifier.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifier
     * @return void
     */
    private function registerTrustedMethod(?Identity $identity, ?string $identifier = null): void
    {
        $method = new class ($identity, $identifier) implements SignInMethod {
            /**
             * Constructor.
             *
             * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
             * @param  ?string  $identifier
             */
            public function __construct(

                /** Identity the method vouches for. */
                private readonly ?Identity $identity,

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
             * Vouch for the configured identity.
             *
             * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
             * @return \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason
             */
            #[\Override]
            public function authenticate(SignInRequest $request): Identity|SignInFailureReason
            {
                return $this->identity ?? SignInFailureReason::INVALID_CREDENTIALS;
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
