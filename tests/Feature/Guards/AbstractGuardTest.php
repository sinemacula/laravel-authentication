<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Stringable;
use Illuminate\Support\Timebox;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Factors\FirstFactorMeetsRequirements;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Unit\Stubs\PlainTenantFixture;
use Tests\Unit\Stubs\StubCredentialGuard;
use Tests\Unit\Stubs\StubRequestResolvingGuard;
use Tests\Unit\Stubs\StubSession;

/**
 * Feature tests for the sign-in policy `attempt()` applies on top of the
 * password sign-in method.
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

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy The application policy in the container. */
    private MockInterface $policy;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\ApplicationAccess The application access in the container. */
    private MockInterface $access;

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

        $this->policy  = \Mockery::mock(ApplicationPolicy::class);
        $this->limiter = \Mockery::mock(AttemptLimiter::class);
        $this->factors = \Mockery::mock(AdditionalFactorPolicy::class);

        $this->policy->shouldReceive('allowsMethod')->byDefault()->andReturnUsing(fn (): bool => $this->record('allowsMethod', true));
        $this->policy->shouldReceive('admitIdentifier')->byDefault()->andReturnUsing(fn (): mixed => $this->record('admitIdentifier', null));
        $this->limiter->shouldReceive('acquire')
            ->byDefault()
            ->andReturnUsing(fn (AttemptSubject $subject): AttemptReservation => $this->record('acquire', new AttemptReservation($subject, null)));
        $this->limiter->shouldReceive('release')->byDefault()->andReturnUsing(fn (): mixed => $this->record('release', null));
        $this->factors->shouldReceive('requirementFor')->byDefault()->andReturnUsing(fn (): Requirement => $this->record('requirementFor', new Requirement));

        assert($this->app !== null);

        $this->access = \Mockery::mock(ApplicationAccess::class);
        $this->access->shouldReceive('mayUse')->byDefault()->andReturnUsing(fn (): bool => $this->record('mayUse', true));

        $this->app->instance(ApplicationPolicy::class, $this->policy);
        $this->app->instance(ApplicationAccess::class, $this->access);
        $this->app->instance(AttemptLimiter::class, $this->limiter);
        $this->app->instance(AdditionalFactorPolicy::class, $this->factors);

        $this->request->shouldReceive('ip')->andReturn(self::IP);

        $this->events->shouldReceive('dispatch')->byDefault();
    }

    /**
     * A successful attempt runs every check in order and only then gives back
     * both reservations.
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

        $this->policy->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'password')->andReturnUsing(fn (): bool => $this->record('allowsMethod', true));
        $this->policy->shouldReceive('admitIdentifier')
            ->once()
            ->with(self::GUARD_NAME, $identity, 'email')
            ->andReturnUsing(fn (): mixed => $this->record('admitIdentifier', null));
        $this->access->shouldReceive('mayUse')->once()->with(self::GUARD_NAME, $principal)->andReturnUsing(fn (): bool => $this->record('mayUse', true));

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
                'admitIdentifier',
                'mayUse',
                'rehashPasswordIfRequired',
                'requirementFor',
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
        $this->policy->shouldReceive('allowsMethod')->once()->with(self::GUARD_NAME, 'password')->andReturnFalse();
        $this->limiter->shouldNotReceive('acquire');
        $this->provider->shouldNotReceive('retrieveByCredentials');
        $this->timebox->shouldNotReceive('call');

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertSame([Attempting::class, Failed::class, AuthenticationFailed::class], array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));

        $failed = $events[1];
        $signIn = $events[2];

        self::assertInstanceOf(Failed::class, $failed);
        self::assertNull($failed->user);
        self::assertSame(['email' => 'ada@example.test'], $failed->credentials);

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $signIn->reason);
        self::assertSame(self::GUARD_NAME, $signIn->context->guard);
        self::assertSame('password', $signIn->context->method);
        self::assertSame('ada@example.test', $signIn->identifier);
        self::assertSame(self::IP, $signIn->context->client->ip);
        EventContextAssertions::assertIdentity(null, $signIn->context);
        self::assertNull($signIn->retryAfter);
    }

    /**
     * The identifier is read for the limits only once the method is allowed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentifierIsReadForTheLimitsOnlyOnceTheMethodIsAllowed(): void
    {
        $this->policy->shouldReceive('allowsMethod')->twice()->andReturnValues([false, true]);
        $this->limiter->shouldReceive('acquire')->once()->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, 42));
        $this->provider->shouldNotReceive('retrieveByCredentials');

        $identifier = new class implements \Stringable {
            /** @var int The times the identifier has been read. */
            public int $reads = 0;

            /**
             * Read the identifier, counting the read.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                $this->reads++;

                return 'ada@example.test';
            }
        };

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => $identifier, 'password' => 'secret']));
        self::assertSame(1, $identifier->reads);

        self::assertFalse($this->makeGuard()->attempt(['email' => $identifier, 'password' => 'secret']));
        self::assertSame(3, $identifier->reads);

        $failures = array_values(array_filter($events->getArrayCopy(), static fn (object $event): bool => $event instanceof AuthenticationFailed));

        self::assertSame(
            [[FailureReason::METHOD_NOT_ALLOWED, 'ada@example.test'], [FailureReason::RATE_LIMITED, 'ada@example.test']],
            array_map(static fn (AuthenticationFailed $event): array => [$event->reason, $event->identifier], $failures),
        );
    }

    /**
     * The limiter is resolved before the identifier is read for the limits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLimiterIsResolvedBeforeTheIdentifierIsReadForTheLimits(): void
    {
        $this->policy->shouldReceive('allowsMethod')->once()->andReturnTrue();
        $this->limiter->shouldReceive('acquire')->once()->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, 42));
        $this->provider->shouldNotReceive('retrieveByCredentials');

        $later = \Mockery::mock(AttemptLimiter::class);
        $later->shouldReceive('acquire')->andReturnUsing(static fn (AttemptSubject $subject): AttemptReservation => new AttemptReservation($subject, 99));

        $identifier = new class ($later) implements \Stringable {
            /** @var int The times the identifier has been read. */
            private int $reads = 0;

            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\AttemptLimiter  $later
             */
            public function __construct(

                /** The limiter bound when the identifier is read for the limits. */
                private readonly AttemptLimiter $later,
            ) {}

            /**
             * Read the identifier, binding the later limiter on the second
             * read.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                if (++$this->reads === 2) {
                    app()->instance(AttemptLimiter::class, $this->later);
                }

                return 'ada@example.test';
            }
        };

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => $identifier, 'password' => 'secret']));

        $failures = array_values(array_filter($events->getArrayCopy(), static fn (object $event): bool => $event instanceof AuthenticationFailed));

        self::assertSame(
            [[FailureReason::RATE_LIMITED, 42]],
            array_map(static fn (AuthenticationFailed $event): array => [$event->reason, $event->retryAfter], $failures),
        );
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

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::RATE_LIMITED, $signIn->reason);
        self::assertSame(42, $signIn->retryAfter);
        self::assertSame('ada@example.test', $signIn->identifier);
    }

    /**
     * A failed attempt keeps the slot it took, so it counts towards the limit.
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
     * configured identifier key, whatever the lookup.
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

        $this->policy->shouldReceive('admitIdentifier')->once()->with(self::GUARD_NAME, $identity, 'username')->andReturnNull();
        $this->access->shouldReceive('mayUse')->once()->with(self::GUARD_NAME, $principal)->andReturnTrue();

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
     * An identifier that cannot be counted is refused before any lookup and
     * counts against the IP address only.
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

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $signIn->reason);
        self::assertNull($signIn->identifier);
    }

    /**
     * `Stringable`, integer and closure identifiers are counted and looked up,
     * and each password check is counted against the account.
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
     * An account with no attempts left fails as a wrong password without being
     * checked, while `AuthenticationFailed` reports the limit.
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
        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $signIn->reason);
        self::assertSame(90, $signIn->retryAfter);
        EventContextAssertions::assertIdentity(null, $signIn->context);
    }

    /**
     * An `ApplicationAccess` refusal fails the attempt as
     * `principal_ineligible` and binds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationAccessRefusalFailsTheAttempt(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $this->access->shouldReceive('mayUse')->once()->andReturnFalse();
        $this->factors->shouldNotReceive('requirementFor');
        $this->provider->shouldNotReceive('rehashPasswordIfRequired');
        $this->expectNoSlotGivenBack();

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertFalse($guard->hasUser());

        $classes = array_map(static fn (object $event): string => $event::class, $events->getArrayCopy());

        self::assertSame([Attempting::class, Validated::class, Failed::class, AuthenticationFailed::class], $classes);

        [, , $failed, $signIn] = $events->getArrayCopy();

        self::assertInstanceOf(Failed::class, $failed);
        self::assertSame($identity, $failed->user);
        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $signIn->reason);
        EventContextAssertions::assertIdentity($identity, $signIn->context);
        EventContextAssertions::assertPrincipal($principal, $signIn->context);
    }

    /**
     * A required factor the password alone does not meet fails the attempt,
     * since `attempt()` cannot leave a session pending.
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

        $this->factors->shouldReceive('requirementFor')->once()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): Requirement {
            $asked = $context;

            return new Requirement(new RequirementPart);
        });
        $this->expectNoSlotGivenBack();

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertFalse($guard->hasUser());
        self::assertNotContains(Login::class, array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));

        self::assertInstanceOf(AdditionalFactorContext::class, $asked);
        self::assertSame(self::GUARD_NAME, $asked->application);
        self::assertSame($identity, $asked->identity);
        self::assertSame('password', $asked->firstFactor->method);
        self::assertSame(ChannelKind::PASSWORD, $asked->firstFactor->channel->kind);
        self::assertSame(self::IP, $asked->client->ip);
        self::assertNull($asked->clientName);
        self::assertNull($asked->platform);
        self::assertNull($asked->provenSession);

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $signIn->reason);
        EventContextAssertions::assertPrincipal($principal, $signIn->context);
    }

    /**
     * A requirement the password alone meets lets the attempt through.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequirementThePasswordMeetsLetsTheAttemptThrough(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();

        $this->expectPasswordAccepted($identity);
        $this->provider->shouldReceive('rehashPasswordIfRequired')->twice();

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $this->factors->shouldReceive('requirementFor')->once()->andReturn(new Requirement(new RequirementPart));

        $check = new ProofJudgingRequirementCheck;

        app()->instance(RequirementCheck::class, new FirstFactorMeetsRequirements);

        self::assertTrue($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));

        app()->instance(RequirementCheck::class, $check);

        $this->expectPasswordAccepted($identity);
        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);
        $this->factors->shouldReceive('requirementFor')->once()->andReturn(new Requirement(new RequirementPart));

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));

        [$subject] = $check->judged;

        self::assertNull($subject->session);
        self::assertSame(ProofKind::FIRST_FACTOR, $subject->firstFactor->kind);
        self::assertSame(ChannelKind::PASSWORD, $subject->firstFactor->channel->kind);
        self::assertSame([$subject->firstFactor], $subject->proofs());
    }

    /**
     * The additional-factor policy is asked about the identity alone, whatever
     * principal and tenant the attempt admitted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorPolicyIsAskedAboutTheIdentityAlone(): void
    {
        $identity = $this->mockIdentity();
        $tenant   = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->byDefault()->andReturn('tenant-1');
        $principal = $this->mockActivePrincipal();
        $principal->shouldReceive('getTenant')->andReturn($tenant);

        $this->expectPasswordAccepted($identity);
        $this->provider->shouldReceive('rehashPasswordIfRequired')->once();

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $asked = null;

        $this->factors->shouldReceive('requirementFor')->once()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): Requirement {
            $asked = $context;

            return new Requirement;
        });

        self::assertTrue($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
        self::assertInstanceOf(AdditionalFactorContext::class, $asked);
        self::assertSame($identity, $asked->identity);
        self::assertSame(['application', 'identity', 'firstFactor', 'client', 'clientName', 'platform', 'provenSession'], array_keys(get_object_vars($asked)));
    }

    /**
     * A pinned session that is not one of the identity's live sessions fails
     * the attempt as a session mismatch, before the factor policy is asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPinnedSessionTheIdentityDoesNotHoldFailsAsASessionMismatch(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();
        $session   = $this->mockSession();
        $session->shouldReceive('getSessionIdentifier')->andReturn('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70');

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $this->factors->shouldNotReceive('requirementFor');

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $session));

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::SESSION_MISMATCH, $signIn->reason);
        EventContextAssertions::assertPrincipal($principal, $signIn->context);
        EventContextAssertions::assertSession(null, $signIn->context);
    }

    /**
     * `attempt()` with a pinned session admits the principal in the tenant the
     * session records, or fails as `tenant_inactive`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPinnedSessionIsAdmittedInTheTenantItRecords(): void
    {
        $sessionId = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f71';

        $principal = $this->mockActivePrincipal();
        $own       = $this->pinnableSession($sessionId, $principal);
        $elsewhere = $this->pinnableSession($sessionId, $principal)->forceFill(['tenant_id' => 'tenant-2']);

        $sessions = \Mockery::mock(Builder::class);
        $sessions->shouldReceive('useWritePdo')->andReturnSelf();
        $sessions->shouldReceive('getModel')->andReturn(new StubSession);
        $sessions->shouldReceive('find')->with($sessionId)->andReturn($own, $elsewhere);

        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldReceive('sessions')->andReturn($sessions);

        $this->provider->shouldReceive('retrieveByCredentials')->twice()->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->twice()->andReturnTrue();

        $this->resolver->shouldReceive('resolve')->twice()->andReturn($principal);

        $guard = $this->makeGuard();

        self::assertTrue($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $own));
        self::assertNull($guard->tenant());

        $events  = $this->recordEvents();
        $refused = $this->makeGuard();

        self::assertFalse($refused->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $own));
        self::assertFalse($refused->hasUser());

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::TENANT_INACTIVE, $signIn->reason);
        EventContextAssertions::assertSession($elsewhere, $signIn->context);
    }

    /**
     * A pinned session in a tenant `TenantAccess` no longer allows fails as
     * `tenant_ineligible` and binds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPinnedSessionInATenantTheAccessNoLongerAllowsIsIneligible(): void
    {
        $sessionId = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f72';

        $principal = $this->mockActivePrincipal();
        $session   = $this->pinnableSession($sessionId, $principal)->forceFill(['tenant_id' => 'tenant-2']);
        $elsewhere = new PlainTenantFixture('tenant-2');

        $sessions = \Mockery::mock(Builder::class);
        $sessions->shouldReceive('useWritePdo')->andReturnSelf();
        $sessions->shouldReceive('getModel')->andReturn(new StubSession);
        $sessions->shouldReceive('find')->with($sessionId)->andReturn($session);

        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldReceive('sessions')->andReturn($sessions);

        $this->expectPasswordAccepted($identity);
        $this->resolver->shouldReceive('resolve')->once()->andReturn($principal);

        $resolver = \Mockery::mock(TenantResolver::class);
        $resolver->shouldReceive('resolve')->with('tenant-2')->andReturn($elsewhere);
        $access = \Mockery::mock(TenantAccess::class);
        $access->shouldReceive('mayActIn')->with($principal, null)->andReturnTrue();
        $access->shouldReceive('mayActIn')->once()->with($principal, $elsewhere)->andReturnFalse();

        assert($this->app !== null);

        $this->app->instance(TenantResolver::class, $resolver);
        $this->app->instance(TenantAccess::class, $access);

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $session));
        self::assertFalse($guard->hasUser());

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::TENANT_INELIGIBLE, $signIn->reason);
        EventContextAssertions::assertSession($session, $signIn->context);
    }

    /**
     * A pinned session is bound but never shown to the factor policy, since
     * naming a session proves nothing about who holds the client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPinnedSessionIsNeverShownToTheFactorPolicy(): void
    {
        $sessionId = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

        $principal = $this->mockActivePrincipal();
        $session   = $this->pinnableSession($sessionId, $principal);

        $sessions = \Mockery::mock(Builder::class);
        $sessions->shouldReceive('useWritePdo')->andReturnSelf();
        $sessions->shouldReceive('getModel')->andReturn(new StubSession);
        $sessions->shouldReceive('find')->with($sessionId)->andReturn($session);

        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldReceive('sessions')->andReturn($sessions);

        $this->provider->shouldReceive('retrieveByCredentials')->twice()->andReturn($identity);
        $this->provider->shouldReceive('validateCredentials')->twice()->andReturnTrue();

        $this->resolver->shouldReceive('resolve')->twice()->andReturn($principal);

        $asked = [];

        $this->factors->shouldReceive('requirementFor')->twice()->andReturnUsing(static function (AdditionalFactorContext $context) use (&$asked): Requirement {
            $asked[] = $context->provenSession;

            return count($asked) === 2 ? new Requirement(new RequirementPart) : new Requirement;
        });

        $guard = $this->makeGuard();

        self::assertTrue($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $session));
        self::assertSame($session, $guard->session());

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret'], null, $session));
        self::assertSame([null, null], $asked);

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $signIn->reason);
        EventContextAssertions::assertSession($session, $signIn->context);
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

        $replacement = \Mockery::mock(ApplicationPolicy::class);
        $replacement->shouldReceive('allowsMethod')->once()->andReturnFalse();

        $this->policy->shouldNotReceive('allowsMethod');

        assert($this->app !== null);

        $this->app->instance(ApplicationPolicy::class, $replacement);

        self::assertFalse($guard->attempt(['email' => 'ada@example.test', 'password' => 'secret']));
    }

    /**
     * `validate()` checks only the credentials: no limit, application policy or
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

        $this->policy->shouldNotReceive('allowsMethod');
        $this->policy->shouldNotReceive('admitIdentifier');
        $this->access->shouldNotReceive('mayUse');
        $this->limiter->shouldNotReceive('acquire');
        $this->factors->shouldNotReceive('requirementFor');
        $this->provider->shouldNotReceive('rehashPasswordIfRequired');

        self::assertTrue($this->makeGuard()->validate(['email' => 'ada@example.test', 'password' => 'secret']));
    }

    /**
     * The timebox is cut short only for a sign-in that succeeds, and
     * `validate()` fires `Validated` only for credentials it accepts.
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
        $this->factors->shouldReceive('requirementFor')->andReturn(new Requirement, new Requirement(new RequirementPart));

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
            static fn (AuthenticationFailed $event): FailureReason => $event->reason,
            array_values(array_filter($events->getArrayCopy(), static fn (object $event): bool => $event instanceof AuthenticationFailed)),
        );

        self::assertSame([FailureReason::PRINCIPAL_UNRESOLVED, FailureReason::PRINCIPAL_MISMATCH], $reasons);
    }

    /**
     * A sign-in refused for its principal fails with that reason without
     * looking its pinned session up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedPrincipalFailsBeforeThePinnedSessionIsLookedUp(): void
    {
        $identity = $this->mockIdentity(HasSessions::class);
        $identity->shouldNotReceive('sessions');

        $pinned = $this->mockActivePrincipal();
        $pinned->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');

        $session = $this->mockSession();
        $session->shouldNotReceive('getSessionIdentifier');

        $this->expectPasswordAccepted($identity);

        $this->resolver->shouldReceive('resolve')->once()->andReturnNull();

        $events = $this->recordEvents();

        self::assertFalse($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret'], $pinned, $session));

        $signIn = $events[count($events) - 1];

        self::assertInstanceOf(AuthenticationFailed::class, $signIn);
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $signIn->reason);
    }

    /**
     * A successful attempt binds as a password sign-in, reporting the
     * `password` method and the admitted tenant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulAttemptBindsAsAPasswordSignIn(): void
    {
        $identity  = $this->mockIdentity();
        $principal = $this->mockActivePrincipal();
        $tenant    = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn('tenant-9');
        $principal->shouldReceive('getTenant')->andReturn($tenant);

        $this->expectPasswordAccepted($identity);
        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($principal);

        $events = $this->recordEvents();

        self::assertTrue($this->makeGuard()->attempt(['email' => 'ada@example.test', 'password' => 'secret']));

        $classes = array_map(static fn (object $event): string => $event::class, $events->getArrayCopy());

        self::assertSame([Attempting::class, Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class], $classes);

        $login    = $events[2];
        $assigned = $events[4];

        self::assertInstanceOf(Login::class, $login);
        self::assertFalse($login->remember);
        self::assertInstanceOf(PrincipalAssigned::class, $assigned);
        self::assertSame('password', $assigned->context->method);
        EventContextAssertions::assertTenant($tenant, $assigned->context);
    }

    /**
     * The `bindAuthenticationLifecycle()` hook binds a sign-in whose events
     * report the session's method, or none without a session.
     *
     * @return void
     */
    public function testTheLifecycleHookBindsASignInWithTheSessionsMethod(): void
    {
        $guard   = new StubCredentialGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);
        $session = $this->mockSession();
        $session->shouldReceive('getSignInMethod')->andReturn('passkey');

        $events = $this->recordEvents();

        $guard->bindResolvedContext($this->mockIdentity(), $this->mockPrincipal(), $session);

        $withSession = $events->getArrayCopy();

        $events->exchangeArray([]);

        $guard->bindResolvedContext($this->mockIdentity(), $this->mockPrincipal());

        $withoutSession = $events->getArrayCopy();

        $classes = array_map(static fn (object $event): string => $event::class, $withSession);

        self::assertSame([Login::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class], $classes);
        self::assertInstanceOf(Login::class, $withSession[0]);
        self::assertFalse($withSession[0]->remember);
        self::assertInstanceOf(SessionAuthenticated::class, $withSession[3]);
        self::assertSame('passkey', $withSession[3]->context->method);
        self::assertSame([Login::class, Authenticated::class, PrincipalAssigned::class], array_map(static fn (object $event): string => $event::class, $withoutSession));
        self::assertInstanceOf(PrincipalAssigned::class, $withoutSession[2]);
        self::assertNull($withoutSession[2]->context->method);
        self::assertNull($guard->session());
    }

    /**
     * The `bindVerifiedContext()` hook binds a credential's context without
     * `Login`, limited to and reporting its scopes.
     *
     * @return void
     */
    public function testTheVerifiedContextHookBindsACredentialsScopes(): void
    {
        $guard  = new StubCredentialGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);
        $events = $this->recordEvents();

        $guard->bindCredential($this->mockIdentity(MachineIdentity::class), $this->mockPrincipal(), 'key-1', ['invoices:read']);

        self::assertSame([Authenticated::class, PrincipalAssigned::class], array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));
        self::assertInstanceOf(PrincipalAssigned::class, $events[1]);
        self::assertSame('key-1', $events[1]->context->credentialId);
        self::assertSame(['invoices:read'], $events[1]->context->scopes);
        self::assertSame('api_key', $events[1]->context->method);
        self::assertSame(['invoices:read'], $guard->scopes());
    }

    /**
     * `authenticateAs()` without a session binds with no method and no session
     * event.
     *
     * @return void
     */
    public function testAuthenticateAsWithoutASessionReportsNoMethod(): void
    {
        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($this->mockIdentity(), $this->mockPrincipal());

        self::assertSame([Authenticated::class, PrincipalAssigned::class], array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()));
        self::assertInstanceOf(PrincipalAssigned::class, $events[1]);
        self::assertNull($events[1]->context->method);
        EventContextAssertions::assertSession(null, $events[1]->context);
    }

    /**
     * `authenticateAs()` binds the tenant it is given as given, over the
     * principal's own; without one, the principal's own.
     *
     * @return void
     */
    public function testAuthenticateAsBindsTheTenantGivenOverThePrincipalsOwn(): void
    {
        $own       = new PlainTenantFixture(7);
        $given     = new PlainTenantFixture(9);
        $principal = $this->mockPrincipal();
        $principal->shouldReceive('getTenant')->andReturn($own);
        $guard = $this->makeGuard();

        $guard->authenticateAs($this->mockIdentity(), $principal, null, null, $given);

        self::assertSame($given, $guard->tenant());

        $guard->authenticateAs($this->mockIdentity(), $principal);

        self::assertSame($own, $guard->tenant());
    }

    /**
     * `authenticateAs()` refuses scopes for a human identity, which no
     * credential limits, and binds nothing.
     *
     * @return void
     */
    public function testAuthenticateAsRefusesScopesForAHuman(): void
    {
        $events = $this->recordEvents();

        try {
            $this->makeGuard()->authenticateAs($this->mockIdentity(), $this->mockPrincipal(), null, ['invoices:read']);
            self::fail('A human identity was bound with scopes.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Scopes limit the credential of a machine identity; ', $exception->getMessage());
        }

        self::assertSame([], $events->getArrayCopy());
    }

    /**
     * Every credential check first clears an early return an earlier success
     * asked of the timebox.
     *
     * @return void
     */
    public function testACredentialCheckClearsAnEarlierEarlyReturnFirst(): void
    {
        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('dontReturnEarly')->once()->ordered()->andReturnSelf();
        $this->timebox->shouldReceive('call')->once()->ordered()->andReturn(false);

        self::assertFalse($this->makeGuard()->validate(['email' => 'ada@example.test', 'password' => 'irrelevant']));
    }

    /**
     * `forgetUser()` quietly signs the guard out for the rest of the request
     * and returns the guard.
     *
     * @return void
     */
    public function testForgetUserSignsTheGuardOutQuietlyForTheRestOfTheRequest(): void
    {
        $identity = $this->mockIdentity();
        $guard    = new StubRequestResolvingGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);

        $guard->resolvable = $identity;

        $this->events->shouldReceive('dispatch')->byDefault();

        self::assertSame($identity, $guard->user());
        self::assertSame(1, $guard->resolutions);

        $this->events->shouldNotReceive('dispatch');

        self::assertSame($guard, $guard->forgetUser());

        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->session());
        self::assertTrue($guard->guest());
        self::assertSame(1, $guard->resolutions);
    }

    /**
     * `setUser()` binds the identity's default principal with no session and
     * reports the bind once it is whole.
     *
     * @return void
     */
    public function testSetUserBindsTheDefaultPrincipalAndReportsIt(): void
    {
        $guard     = $this->makeGuard();
        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $seen      = [];

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($principal);

        $this->events->shouldReceive('dispatch')->andReturnUsing(static function (object $event) use ($guard, &$seen): void {
            $seen[] = [$event::class, $guard->principal()];
        });

        self::assertSame($guard, $guard->setUser($identity));
        self::assertSame($identity, $guard->identity());
        self::assertSame($principal, $guard->principal());
        self::assertNull($guard->session());
        self::assertSame([[Authenticated::class, $principal], [PrincipalAssigned::class, $principal]], $seen);
    }

    /**
     * `setUser()` over a credential's context forgets that context and the
     * credential kind it was made with.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSetUserForgetsTheCredentialAndTheContextHeldBeforeIt(): void
    {
        $this->events->shouldReceive('dispatch');

        $guard = new StubCredentialGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);

        $guard->bindCredential($this->mockIdentity(MachineIdentity::class), $this->mockPrincipal(), 'key-1', ['invoices:read']);

        $before = $guard->authenticationContext();

        self::assertSame(CredentialKind::API_KEY, $before?->credential);

        $identity = $this->mockIdentity();

        $identity->shouldReceive('getAuthIdentifier')->andReturn(2);

        $this->resolver->shouldReceive('resolve')->once()->with($identity)->andReturn($this->mockPrincipal());

        $guard->setUser($identity);

        $after = $guard->authenticationContext();

        self::assertNotNull($after);
        self::assertNotSame($before, $after);
        self::assertSame('2', $after->identityId);
        self::assertSame(SubjectType::PERSON, $after->subjectType);
        self::assertNull($after->credential);
        self::assertNull($after->scopes);
    }

    /**
     * `login()` given a client describes that client in its bind events for
     * that bind only.
     *
     * @return void
     */
    public function testLoginWithAClientDescribesThatClientForThatBindOnly(): void
    {
        $this->request->shouldReceive('userAgent')->andReturn('Request/1.0');

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $session   = $this->mockSession();
        $client    = new ClientContext('198.51.100.4', 'Worker/3.1');

        $session->shouldReceive('getSignInMethod')->andReturn('password');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->login($identity, $principal, $session, $client);

        self::assertSame(
            [Validated::class, Login::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class],
            array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()),
        );
        self::assertSame($identity, $events[0]->user ?? null);
        self::assertSame($identity, $events[1]->user ?? null);
        self::assertSame($client, $events[3]->context->client ?? null);
        self::assertSame($client, $events[4]->context->client ?? null);
        self::assertSame([$identity, $principal, $session], [$guard->user(), $guard->principal(), $guard->session()]);

        $events->exchangeArray([]);

        $guard->login($identity, $principal, $session);

        self::assertSame([self::IP, 'Request/1.0'], [$events[3]->context->client->ip ?? null, $events[3]->context->client->userAgent ?? null]);
        self::assertSame([self::IP, 'Request/1.0'], [$events[4]->context->client->ip ?? null, $events[4]->context->client->userAgent ?? null]);
    }

    /**
     * `authenticateAs()` given a client describes that client in its bind
     * events for that bind only.
     *
     * @return void
     */
    public function testAuthenticateAsWithAClientDescribesThatClientForThatBindOnly(): void
    {
        $this->request->shouldReceive('userAgent')->andReturn('Request/1.0');

        $identity  = $this->mockIdentity();
        $principal = $this->mockPrincipal();
        $session   = $this->mockSession();
        $client    = new ClientContext('198.51.100.4', 'Worker/3.1');

        $session->shouldReceive('getSignInMethod')->andReturn('password');

        $events = $this->recordEvents();
        $guard  = $this->makeGuard();

        $guard->authenticateAs($identity, $principal, $session, client: $client);

        self::assertSame(
            [Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class],
            array_map(static fn (object $event): string => $event::class, $events->getArrayCopy()),
        );
        self::assertSame($identity, $events[0]->user ?? null);
        self::assertSame($client, $events[1]->context->client ?? null);
        self::assertSame($client, $events[2]->context->client ?? null);
        self::assertSame([$identity, $principal, $session], [$guard->user(), $guard->principal(), $guard->session()]);

        $events->exchangeArray([]);

        $guard->authenticateAs($identity, $principal, $session);

        self::assertSame([self::IP, 'Request/1.0'], [$events[1]->context->client->ip ?? null, $events[1]->context->client->userAgent ?? null]);
        self::assertSame([self::IP, 'Request/1.0'], [$events[2]->context->client->ip ?? null, $events[2]->context->client->userAgent ?? null]);
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
     * Expect the attempt to give back no slot, as any failure after the
     * password was accepted does.
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
