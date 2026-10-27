<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Carbon;
use Illuminate\Support\Stringable;
use Illuminate\Support\Timebox;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use Tests\Unit\Stubs\StubDevice;

/**
 * Feature tests for the sign-in policy `attempt()` applies on top of the
 * password sign-in method: the audience policy's method check and admission,
 * the attempt limits, the additional-factor policy, and the failure events that
 * report each refusal.
 *
 * The policies are resolved from the container when `attempt()` runs, so each
 * test binds its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class AbstractGuardTest extends AbstractGuardTestCase
{
    /** @var string IP address the sign-in request comes from. */
    private const string IP = '203.0.113.7';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AudiencePolicy The audience policy in the container. */
    private MockInterface $audience;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AttemptLimiter The attempt limiter in the container. */
    private MockInterface $limiter;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy The additional-factor policy in the container. */
    private MockInterface $factors;

    /** @var list<string> The calls made to the policies and the provider, in order. */
    private array $calls = [];

    /**
     * Bind permissive policy mocks that record their calls, and a request from
     * a known IP address.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->audience = \Mockery::mock(AudiencePolicy::class);
        $this->limiter  = \Mockery::mock(AttemptLimiter::class);
        $this->factors  = \Mockery::mock(AdditionalFactorPolicy::class);

        $this->audience->shouldReceive('allowsMethod')->byDefault()->andReturnUsing(fn (): bool => $this->record('allowsMethod', true));
        $this->audience->shouldReceive('admit')->byDefault()->andReturnUsing(fn (): mixed => $this->record('admit', null));
        $this->limiter->shouldReceive('acquire')
            ->byDefault()
            ->andReturnUsing(fn (AttemptSubject $subject): AttemptReservation => $this->record('acquire', new AttemptReservation($subject, null)));
        $this->limiter->shouldReceive('release')->byDefault()->andReturnUsing(fn (): mixed => $this->record('release', null));
        $this->factors->shouldReceive('requiresAdditionalFactor')->byDefault()->andReturnUsing(fn (): bool => $this->record('requiresAdditionalFactor', false));

        assert($this->app !== null);

        $this->app->instance(AudiencePolicy::class, $this->audience);
        $this->app->instance(AttemptLimiter::class, $this->limiter);
        $this->app->instance(AdditionalFactorPolicy::class, $this->factors);

        $this->request->shouldReceive('ip')->andReturn(self::IP);

        $this->events->shouldReceive('dispatch')->byDefault();
    }

    /**
     * A successful attempt asks the audience policy for the method first, then
     * reserves an attempt, finds the account, reserves an attempt on the
     * account, checks the password, admits the identity, rehashes the password
     * with the credentials it signed in with, asks the factor policy, and only
     * then gives both reservations back, the attempt's and the account's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulAttemptRunsEveryCheckInOrderAndGivesItsSlotBack(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $this->expectPasswordAccepted($identity);

        $this->provider->shouldReceive('rehashPasswordIfRequired')
            ->once()
            ->with($identity, ['email' => 'Ada@Example.test', 'password' => 'secret'])
            ->andReturnUsing(fn (): mixed => $this->record('rehashPasswordIfRequired', null));

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($principal);

        $this->audience->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'password')->andReturnUsing(fn (): bool => $this->record('allowsMethod', true));
        $this->audience->shouldReceive('admit')->once()->with(self::GUARD_NAME, $identity, $principal, 'email')->andReturnUsing(fn (): mixed => $this->record('admit', null));

        $reservations = [];

        $this->limiter->shouldReceive('acquire')
            ->once()
            ->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->guard === self::GUARD_NAME
                && $subject->flow                                                            === AttemptFlow::SIGN_IN
                && $subject->identifier                                                      === 'Ada@Example.test'
                && $subject->identifierType                                                  === 'email'
                && $subject->ip                                                              === self::IP
                && $subject->account                                                         === null))
            ->andReturnUsing(function (AttemptSubject $subject) use (&$reservations): AttemptReservation {
                $reservations['attempt'] = new AttemptReservation($subject, null, ['k' => 'w']);

                return $this->record('acquire', $reservations['attempt']);
            });
        $this->limiter->shouldReceive('acquire')
            ->once()
            ->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->guard === self::GUARD_NAME
                && $subject->flow                                                            === AttemptFlow::SIGN_IN
                && $subject->identifier                                                      === null
                && $subject->identifierType                                                  === null
                && $subject->ip                                                              === null
                && $subject->account                                                         === AccountAttempts::account($identity)))
            ->andReturnUsing(function (AttemptSubject $subject) use (&$reservations): AttemptReservation {
                $reservations['account'] = new AttemptReservation($subject, null, ['a' => 'w']);

                return $this->record('acquire account', $reservations['account']);
            });
        $this->limiter->shouldReceive('release')
            ->twice()
            ->andReturnUsing(function (AttemptReservation $released) use (&$reservations): mixed {
                return $this->record($released === $reservations['account'] ? 'release account' : ($released === $reservations['attempt'] ? 'release' : 'release other'), null);
            });

        self::assertTrue($this->makeGuard()->attempt(['email' => 'Ada@Example.test', 'password' => 'secret']));
        self::assertSame(
            [
                'allowsMethod',
                'acquire',
                'retrieveByCredentials',
                'acquire account',
                'validateCredentials',
                'admit',
                'rehashPasswordIfRequired',
                'requiresAdditionalFactor',
                'release',
                'release account',
            ],
            $this->calls,
        );
    }

    /**
     * A guard that does not allow the password method refuses the attempt
     * before anything is counted or looked up, and reports why.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMethodTheGuardDoesNotAllowIsRefusedBeforeAnythingIsCounted(): void
    {
        $this->audience->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'password')->andReturnFalse();
        $this->limiter->shouldNotReceive('acquire');
        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->timebox->shouldNotReceive('call');

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertSame([Attempting::class, Failed::class, SignInFailed::class], array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));

        $failed = $events[1];
        $signIn = $events[2];

        self::assertInstanceOf(Failed::class, $failed);
        self::assertNull($failed->user);
        self::assertSame(['email' => 'ada@example.test'], $failed->credentials);

        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::METHOD_NOT_ALLOWED, $signIn->reason);
        self::assertSame(self::GUARD_NAME, $signIn->guard);
        self::assertSame('password', $signIn->method);
        self::assertSame('ada@example.test', $signIn->identifier);
        self::assertSame(self::IP, $signIn->client->ip);
        self::assertNull($signIn->identity);
        self::assertNull($signIn->retryAfter);
    }

    /**
     * An attempt over its limit is refused without checking the credentials,
     * reports the wait, and gives nothing back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARateLimitedAttemptIsRefusedWithoutCheckingTheCredentials(): void
    {
        $this->limiter->shouldReceive('acquire')->once()->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, 42));
        $this->limiter->shouldNotReceive('release');
        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->timebox->shouldNotReceive('call');

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));

        $signIn = $events[2] ?? null;

        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::RATE_LIMITED, $signIn->reason);
        self::assertSame(42, $signIn->retryAfter);
        self::assertSame('ada@example.test', $signIn->identifier);
    }

    /**
     * A failed attempt keeps the slot it took, so it counts toward the limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedAttemptKeepsItsSlot(): void
    {
        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturnNull();
        $this->limiter->shouldReceive('acquire')->once()->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, null));
        $this->limiter->shouldNotReceive('release');

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'wrong']));
    }

    /**
     * The limits count, and the verified-identifier requirement checks, the
     * configured identifier key, whatever else the credentials hold: a lookup
     * written as a closure cannot skip either. Credentials without that key
     * count against the IP address only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheConfiguredIdentifierIsCountedAndCheckedWhateverTheLookup(): void
    {
        config()->set('authentication.sign_in.password_identifier', 'username');

        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();
        $scope     = static fn (): null => null;

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $this->audience->shouldReceive('admit')->once()->with(self::GUARD_NAME, $identity, $principal, 'username')->andReturnNull();

        $subjects = [];

        $this->limiter->shouldReceive('acquire')->times(3)->andReturnUsing(static function (AttemptSubject $subject) use (&$subjects): AttemptReservation {
            if ($subject->account === null) {
                $subjects[] = $subject;
            }

            return new AttemptReservation($subject, null);
        });

        self::assertTrue($this->makeGuard()->attempt(['username' => 'ada', 'password' => 'secret', 'active' => $scope]));

        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturnNull();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret', 'active' => $scope]));

        self::assertSame(['ada', null], array_map(static fn (AttemptSubject $subject): ?string => $subject->identifier, $subjects));
        self::assertSame(['username', 'username'], array_map(static fn (AttemptSubject $subject): ?string => $subject->identifierType, $subjects));
    }

    /**
     * Rows of `[identifier value]` that `attempt()` cannot count against the
     * identifier's limit.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideIdentifiersThatCannotBeCounted(): iterable
    {
        yield from [
            'list'    => [['ada@example.test', 'bob@example.test']],
            'float'   => [0.0],
            'boolean' => [true],
            'null'    => [null],
        ];
    }

    /**
     * Credentials whose identifier key holds anything but a string, a
     * `Stringable`, an integer or a query closure are refused before any
     * lookup, as invalid credentials, and count against the IP address only: a
     * list of addresses would otherwise check a password against accounts the
     * identifier's limit never counts.
     *
     * @param  mixed  $identifier
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIdentifiersThatCannotBeCounted')]
    public function testAnIdentifierThatCannotBeCountedIsRefusedBeforeAnyLookup(mixed $identifier): void
    {
        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->provider->shouldNotReceive('validateCredentials');
        $this->limiter->shouldNotReceive('release');

        $subjects = [];

        $this->limiter->shouldReceive('acquire')->once()->andReturnUsing(static function (AttemptSubject $subject) use (&$subjects): AttemptReservation {
            $subjects[] = $subject;

            return new AttemptReservation($subject, null);
        });

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => $identifier, 'password' => 'secret']));
        self::assertNull($subjects[0]->identifier);
        self::assertSame(self::IP, $subjects[0]->ip);

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $signIn->reason);
        self::assertNull($signIn->identifier);
    }

    /**
     * A `Stringable` identifier is counted as its string and looked up as
     * given, an integer is counted and looked up as its string form (so a
     * database never compares a string column with a number), and a query
     * closure under the identifier key still finds the account; each password
     * check is then counted against the account.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStringableAnIntegerOrAClosureIdentifierIsLookedUp(): void
    {
        $identity    = $this->mockIdentity();
        $stringable  = new Stringable('ada@example.test');
        $scope       = static fn (): null => null;
        $subjects    = [];
        $lookedUpFor = [];

        $this->provider->shouldReceive('retrieveByCredentials')->times(3)->andReturnUsing(static function (array $credentials) use ($identity, &$lookedUpFor): MockInterface {
            $lookedUpFor[] = $credentials['email'];

            return $identity;
        });
        $this->provider->shouldReceive('validateCredentials')->times(3)->andReturnFalse();

        $this->limiter->shouldReceive('acquire')->times(6)->andReturnUsing(static function (AttemptSubject $subject) use (&$subjects): AttemptReservation {
            $subjects[] = $subject;

            return new AttemptReservation($subject, null);
        });

        self::assertFalse($this->makeGuard()->attempt(['email' => $stringable, 'password' => 'wrong']));
        self::assertFalse($this->makeGuard()->attempt(['email' => 42, 'password' => 'wrong']));
        self::assertFalse($this->makeGuard()->attempt(['email' => $scope, 'password' => 'wrong']));
        self::assertSame([$stringable, '42', $scope], $lookedUpFor);
        self::assertSame(['ada@example.test', null, '42', null, null, null], array_map(static fn (AttemptSubject $subject): ?string => $subject->identifier, $subjects));

        $account = AccountAttempts::account($identity);

        self::assertSame([null, $account, null, $account, null, $account], array_map(static fn (AttemptSubject $subject): ?string => $subject->account, $subjects));
    }

    /**
     * An account whose own limit is used up is not checked at all: its password
     * is never compared, and the attempt fails as a wrong password would to the
     * caller (Laravel's `Failed` carries the account found, as for any wrong
     * password), while `SignInFailed` tells server-side listeners the truth:
     * the account's limit refused it, with the wait.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccountWithNoAttemptsLeftFailsAsAWrongPasswordWithoutBeingChecked(): void
    {
        $identity = $this->mockIdentity();

        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturn($identity);
        $this->provider->shouldNotReceive('validateCredentials');
        $this->limiter->shouldNotReceive('release');
        $this->limiter->shouldReceive('acquire')->twice()->andReturnUsing(
            static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, $subject->account === null ? null : 90),
        );

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));

        $failed = $events[count($events) - 2];
        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(Failed::class, $failed);
        self::assertSame($identity, $failed->user);
        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::ACCOUNT_RATE_LIMITED, $signIn->reason);
        self::assertSame(90, $signIn->retryAfter);
        self::assertNull($signIn->identity);
    }

    /**
     * When the audience policy refuses the identity as its principal, the
     * attempt fails with the policy's reason and the whole context, and nothing
     * is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAudiencePolicyRefusalFailsTheAttempt(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $this->audience->shouldReceive('admit')->once()->andReturn(SignInFailureReason::PRINCIPAL_INELIGIBLE);
        $this->factors->shouldNotReceive('requiresAdditionalFactor');
        $this->provider->shouldNotReceive('rehashPasswordIfRequired');
        $this->expectNoSlotGivenBack();

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertFalse($guard->hasUser());

        $classes = array_map(static fn (object $event): string => $event::class, $events->getArrayCopy());

        self::assertSame([Attempting::class, Validated::class, Failed::class, SignInFailed::class], $classes);

        [, , $failed, $signIn] = $events->getArrayCopy();

        self::assertInstanceOf(Failed::class, $failed);
        self::assertSame($identity, $failed->user);
        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $signIn->reason);
        self::assertSame($identity, $signIn->identity);
        self::assertSame($principal, $signIn->principal);
    }

    /**
     * The additional-factor policy is asked about the admitted sign-in with
     * the password method and the request's client, and is never told of a
     * device; when it requires a factor the attempt fails, because
     * `attempt()` cannot hand out a pending sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequiredFactorFailsTheAttempt(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $asked = null;

        $this->factors->shouldReceive('requiresAdditionalFactor')->once()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): bool {
            $asked = $context;

            return true;
        });
        $this->expectNoSlotGivenBack();

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertFalse($guard->hasUser());
        self::assertNotContains(Login::class, array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));

        self::assertInstanceOf(AdditionalFactorContext::class, $asked);
        self::assertSame(self::GUARD_NAME, $asked->guard);
        self::assertSame($identity, $asked->identity);
        self::assertSame($principal, $asked->principal);
        self::assertNull($asked->tenant);
        self::assertSame('password', $asked->method);
        self::assertSame(self::IP, $asked->client->ip);
        self::assertNull($asked->clientName);
        self::assertNull($asked->platform);
        self::assertNull($asked->provenDevice);

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::ADDITIONAL_FACTOR_REQUIRED, $signIn->reason);
        self::assertSame($principal, $signIn->principal);
    }

    /**
     * A pinned device that is not one of the identity's live devices fails the
     * attempt as a device mismatch, before the factor policy is asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPinnedDeviceTheIdentityDoesNotHoldFailsAsADeviceMismatch(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();
        $device    = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')->andReturn('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70');

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $this->factors->shouldNotReceive('requiresAdditionalFactor');

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $device));

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::DEVICE_MISMATCH, $signIn->reason);
        self::assertSame($principal, $signIn->principal);
        self::assertNull($signIn->device);
    }

    /**
     * A pinned device the identity holds is bound, but the factor policy is
     * never told of it, because naming a device proves nothing about who holds
     * the client; when the policy then requires a factor, the failure still
     * reports the device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPinnedDeviceIsNeverShownToTheFactorPolicy(): void
    {
        $deviceId = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

        $device = \Mockery::mock(Device::class);
        $device->shouldReceive('getDeviceIdentifier')->andReturn($deviceId);
        $device->shouldReceive('getGuard')->andReturn(self::GUARD_NAME);
        $device->shouldReceive('getRevokedAt')->andReturnNull();
        $device->shouldReceive('getIdleExpiresAt')->andReturn(Carbon::now()->addDays(90));
        $device->shouldReceive('getAbsoluteExpiresAt')->andReturn(Carbon::now()->addDays(180));

        $devices = \Mockery::mock(Builder::class);
        $devices->shouldReceive('useWritePdo')->andReturnSelf();
        $devices->shouldReceive('getModel')->andReturn(new StubDevice);
        $devices->shouldReceive('find')->with($deviceId)->andReturn($device);

        $identity = $this->mockIdentity(HasDevices::class);
        $identity->shouldReceive('devices')->andReturn($devices);

        $principal = $this->mockActivePrincipal();

        $this->provider->shouldReceive('retrieveByCredentials')->twice()->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->twice()->andReturnTrue();

        $this->resolver->shouldReceive('resolve')->twice()->andReturn($principal);

        $asked = [];

        $this->factors->shouldReceive('requiresAdditionalFactor')->twice()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): bool {
            $asked[] = $context->provenDevice;

            return count($asked) === 2;
        });

        $guard = $this->makeGuard();

        self::assertTrue($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $device));
        self::assertSame($device, $guard->device());

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $device));
        self::assertSame([null, null], $asked);

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::ADDITIONAL_FACTOR_REQUIRED, $signIn->reason);
        self::assertSame($device, $signIn->device);
    }

    /**
     * The policies are resolved when `attempt()` runs, so a binding made after
     * the guard was built is the one used.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPoliciesBoundAfterTheGuardWasBuiltAreUsed(): void
    {
        $guard = $this->makeGuard();

        $replacement = \Mockery::mock(AudiencePolicy::class);
        $replacement->shouldReceive('allowsMethod')->once()->andReturnFalse();

        $this->audience->shouldNotReceive('allowsMethod');

        assert($this->app !== null);

        $this->app->instance(AudiencePolicy::class, $replacement);

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
    }

    /**
     * `validate()` checks only the credentials: no limit, audience policy or
     * factor policy applies, and the password is never rehashed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValidateAppliesNoSignInPolicy(): void
    {
        $identity = $this->mockIdentity();

        $this->expectPasswordAccepted($identity);

        $this->audience->shouldNotReceive('allowsMethod');
        $this->audience->shouldNotReceive('admit');
        $this->limiter->shouldNotReceive('acquire');
        $this->factors->shouldNotReceive('requiresAdditionalFactor');
        $this->provider->shouldNotReceive('rehashPasswordIfRequired');

        self::assertTrue($this->makeGuard()->validate(['email' => 'ada@example.test', 'password' => 'secret']));
    }

    /**
     * The timebox is cut short only for a sign-in that succeeds: a sign-in
     * refused after its password was accepted (a required factor, say) waits it
     * out like a wrong password. `validate()` cuts it short, and fires
     * `Validated`, only for credentials it accepts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTimeboxIsCutShortOnlyForASuccess(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();
        $early     = [];

        $this->timebox->shouldReceive('call')->andReturnUsing(static function (callable $callback) use (&$early): mixed {
            $spy = new class extends Timebox {
                /** @var bool Whether returnEarly() was called. */
                public bool $early = false;

                /**
                 * Record the call.
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

            $result  = $callback($spy);
            $early[] = $spy->early;

            return $result;
        });

        $this->provider->shouldReceive('retrieveByCredentials')->andReturn($identity, $identity, $identity, null);
        $this->provider->shouldReceive('validateCredentials')->andReturnTrue();
        $this->resolver->shouldReceive('resolve')->andReturn($principal);
        $this->factors->shouldReceive('requiresAdditionalFactor')->andReturn(false, true);

        $events = $this->recordEvents();

        self::assertTrue($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));

        $validated = array_filter($events->getArrayCopy(), static fn (object $event): bool => $event instanceof Validated);

        self::assertTrue($this->makeGuard()->validate(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertCount(count($validated) + 1, array_filter($events->getArrayCopy(), static fn (object $event): bool => $event instanceof Validated));
        self::assertFalse($this->makeGuard()->validate(['email' => 'nobody@example.test', 'password' => 'secret']));
        self::assertCount(count($validated) + 1, array_filter($events->getArrayCopy(), static fn (object $event): bool => $event instanceof Validated));

        self::assertSame([true, false, true, false], $early);
    }

    /**
     * A principal that does not resolve fails as unresolved when none was
     * pinned, and as a mismatch when the pinned one is not the identity's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnresolvedPrincipalReportsWhetherOneWasPinned(): void
    {
        $identity = $this->mockIdentity();
        $pinned   = $this->mockActivePrincipal();
        $pinned->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');

        $this->provider->shouldReceive('retrieveByCredentials')->twice()->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->twice()->andReturnTrue();
        $this->resolver->shouldReceive('resolve')->twice()->andReturnNull();

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret'], $pinned));

        $reasons = array_map(
            static fn (SignInFailed $event): SignInFailureReason => $event->reason,
            array_values(array_filter($events->getArrayCopy(), static fn (object $event): bool => $event instanceof SignInFailed)),
        );

        self::assertSame([SignInFailureReason::PRINCIPAL_UNRESOLVED, SignInFailureReason::PRINCIPAL_MISMATCH], $reasons);
    }

    /**
     * A sign-in refused for its principal fails with that reason without
     * looking its pinned device up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedPrincipalFailsBeforeThePinnedDeviceIsLookedUp(): void
    {
        $identity = $this->mockIdentity(HasDevices::class);
        $identity->shouldNotReceive('devices');

        $pinned = $this->mockActivePrincipal();
        $pinned->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');

        $device = \Mockery::mock(Device::class);
        $device->shouldNotReceive('getDeviceIdentifier');

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturnNull();

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret'], $pinned, $device));

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(SignInFailed::class, $signIn);
        self::assertSame(SignInFailureReason::PRINCIPAL_MISMATCH, $signIn->reason);
    }

    /**
     * Expect the provider to find the identity and accept its password, each
     * once, recording both calls.
     *
     * @param  \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     */
    private function expectPasswordAccepted(MockInterface $identity): void
    {
        $this->provider->shouldReceive('retrieveByCredentials')->once()->andReturnUsing(fn (): MockInterface => $this->record('retrieveByCredentials', $identity));
        $this->provider->shouldReceive('validateCredentials')->once()->andReturnUsing(fn (): bool => $this->record('validateCredentials', true));
    }

    /**
     * Expect the attempt to give back no slot: a failure after the password was
     * accepted keeps the attempt's own reservation and the one its password
     * check took on the account, as any failure does.
     *
     * @return void
     */
    private function expectNoSlotGivenBack(): void
    {
        $this->limiter->shouldReceive('release')->never();
    }

    /**
     * Record every event the guard dispatches.
     *
     * @return \ArrayObject<int, object>
     */
    private function recordEvents(): \ArrayObject
    {
        $events = new \ArrayObject;

        $this->events->shouldReceive('dispatch')->andReturnUsing(static function (object $event) use ($events): void {
            $events->append($event);
        });

        return $events;
    }

    /**
     * Record a call and return the value it answers with.
     *
     * @template TValue
     *
     * @param  string  $call
     * @param  TValue  $value
     * @return TValue
     */
    private function record(string $call, mixed $value): mixed
    {
        $this->calls[] = $call;

        return $value;
    }
}
