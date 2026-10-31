<?php

declare(strict_types = 1);

namespace Tests\Feature\Contracts;

use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Passwords\RecordingTimebox;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Pins, case by case, what a password sign-in through `attempt()` and through
 * the session service's `signIn('password')` does: what it answers, the events
 * it dispatches in order (the `Failed` line names the user it carries), whether
 * the credential timebox was padded, cut short or never run, whether an
 * outdated password hash was rehashed, and what became of the slot the sign-in
 * took on the identifier and IP limits and of the one it took on the account's
 * own limit: released, kept by a pending sign-in, consumed (left counted),
 * refused, or never taken.
 *
 * The two entry points share their credential steps; each row holds them to
 * what they did before they shared any, so a difference between the two is the
 * one the row records, not one the sharing made.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
#[CoversClass(SessionService::class)]
final class CredentialAttemptMatrixTest extends TestCase
{
    use InteractsWithMachineClients, InteractsWithSessions, RecordsEventSequences;

    /** @var int The credential timebox budget, in microseconds. */
    private const int BUDGET = 400000;

    /** @var string The message of the exception a throwing listener throws. */
    private const string THROWN = 'a listener threw';

    /** @var string The answer of a sign-in a listener's exception ended. */
    private const string THREW = 'threw: ' . self::THROWN;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        self::createMachineClientsTable();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropMachineClientsTable();

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Rows of `[case, row]`: what `attempt()` does in each case.
     *
     * @return iterable<string, array{0: string, 1: array{result: string, events: list<string>, timebox: string, rehashed: bool, reservation: string, account: string}}>
     */
    public static function provideAttemptRows(): iterable
    {
        yield 'invalid password' => ['invalid password', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Failed api i1', 'AuthenticationFailed api sign_in:invalid_credentials -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'unknown identifier' => ['unknown identifier', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Failed api -', 'AuthenticationFailed api sign_in:invalid_credentials -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'none',
        ]];

        yield 'spent account attempts' => ['spent account attempts', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Failed api i1', 'AuthenticationFailed api sign_in:account_rate_limited -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'refused',
        ]];

        yield 'identifier or IP rate limited' => ['identifier or IP rate limited', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Failed api -', 'AuthenticationFailed api sign_in:rate_limited -/-/-'],
            'timebox'     => 'not run',
            'rehashed'    => false,
            'reservation' => 'refused',
            'account'     => 'none',
        ]];

        yield 'method not allowed' => ['method not allowed', [
            'result'      => 'false',
            'events'      => ['Attempting passwordless', 'Failed passwordless -', 'AuthenticationFailed passwordless sign_in:method_not_allowed -/-/-'],
            'timebox'     => 'not run',
            'rehashed'    => false,
            'reservation' => 'none',
            'account'     => 'none',
        ]];

        yield 'machine identity' => ['machine identity', [
            'result'      => 'false',
            'events'      => ['Attempting machines', 'Failed machines i1', 'AuthenticationFailed machines sign_in:invalid_credentials -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'none',
        ]];

        yield 'inactive identity' => ['inactive identity', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Validated api i1', 'Failed api i1', 'AuthenticationFailed api sign_in:identity_inactive i1/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'pinned principal mismatch' => ['pinned principal mismatch', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Validated api i1', 'Failed api i1', 'AuthenticationFailed api sign_in:principal_mismatch i1/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'no default principal' => ['no default principal', [
            'result'      => 'false',
            'events'      => ['Attempting choosers', 'Validated choosers i1', 'Failed choosers i1', 'AuthenticationFailed choosers sign_in:principal_unresolved i1/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'pinned device mismatch' => ['pinned device mismatch', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Validated api i1', 'Failed api i1', 'AuthenticationFailed api sign_in:device_mismatch i1/p1/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'factor required' => ['factor required', [
            'result'      => 'false',
            'events'      => ['Attempting api', 'Validated api i1', 'Failed api i1', 'AuthenticationFailed api sign_in:additional_factor_required i1/p1/-'],
            'timebox'     => 'padded',
            'rehashed'    => true,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'success' => ['success', [
            'result'      => 'true',
            'events'      => ['Attempting api', 'Validated api i1', 'Login api i1', 'Authenticated api i1', 'PrincipalAssigned api i1/p1/-'],
            'timebox'     => 'cut short',
            'rehashed'    => true,
            'reservation' => 'released',
            'account'     => 'released',
        ]];

        yield 'throwing Validated listener' => ['throwing Validated listener', [
            'result'      => self::THREW,
            'events'      => ['Attempting api', 'Validated api i1'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'throwing Login listener' => ['throwing Login listener', [
            'result'      => self::THREW,
            'events'      => ['Attempting api', 'Validated api i1', 'Login api i1'],
            'timebox'     => 'cut short',
            'rehashed'    => true,
            'reservation' => 'released',
            'account'     => 'released',
        ]];
    }

    /**
     * `attempt()` answers, reports, times, rehashes and counts each case as its
     * row says.
     *
     * @param  string  $case
     * @param  array{result: string, events: list<string>, timebox: string, rehashed: bool, reservation: string, account: string}  $row
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAttemptRows')]
    public function testAnAttemptDoesWhatItsRowSays(string $case, array $row): void
    {
        $arranged = $this->arrange($case);

        [$box, $limiter] = $this->instrument($case);

        $guard = $this->freshGuard($arranged['guard']);

        $this->record($case, $arranged['subject']);

        $result = self::answerOf(static fn (): string => $guard->attempt($arranged['credentials'], $arranged['principal'], $arranged['device']) ? 'true' : 'false');

        self::assertSame($row, $this->observed($result, $arranged['subject'], $box, $limiter));
    }

    /**
     * Rows of `[case, row]`: what the session service's `signIn('password')`
     * does in each case. A pinned device is `attempt()`'s alone.
     *
     * @return iterable<string, array{0: string, 1: array{result: string, events: list<string>, timebox: string, rehashed: bool, reservation: string, account: string}}>
     */
    public static function provideSignInRows(): iterable
    {
        yield 'invalid password' => ['invalid password', [
            'result'      => 'failed invalid_credentials',
            'events'      => ['Attempting api', 'Failed api -', 'AuthenticationFailed api sign_in:invalid_credentials -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'unknown identifier' => ['unknown identifier', [
            'result'      => 'failed invalid_credentials',
            'events'      => ['Attempting api', 'Failed api -', 'AuthenticationFailed api sign_in:invalid_credentials -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'none',
        ]];

        yield 'spent account attempts' => ['spent account attempts', [
            'result'      => 'failed invalid_credentials',
            'events'      => ['Attempting api', 'Failed api -', 'AuthenticationFailed api sign_in:account_rate_limited -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'refused',
        ]];

        yield 'identifier or IP rate limited' => ['identifier or IP rate limited', [
            'result'      => 'failed rate_limited 60',
            'events'      => ['Attempting api', 'Failed api -', 'AuthenticationFailed api sign_in:rate_limited -/-/-'],
            'timebox'     => 'not run',
            'rehashed'    => false,
            'reservation' => 'refused',
            'account'     => 'none',
        ]];

        yield 'method not allowed' => ['method not allowed', [
            'result'      => 'failed method_not_allowed',
            'events'      => ['Attempting passwordless', 'Failed passwordless -', 'AuthenticationFailed passwordless sign_in:method_not_allowed -/-/-'],
            'timebox'     => 'not run',
            'rehashed'    => false,
            'reservation' => 'none',
            'account'     => 'none',
        ]];

        yield 'machine identity' => ['machine identity', [
            'result'      => 'failed invalid_credentials',
            'events'      => ['Attempting machines', 'Failed machines -', 'AuthenticationFailed machines sign_in:invalid_credentials -/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'none',
        ]];

        yield 'inactive identity' => ['inactive identity', [
            'result'      => 'failed identity_inactive',
            'events'      => ['Attempting api', 'Failed api i1', 'AuthenticationFailed api sign_in:identity_inactive i1/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'pinned principal mismatch' => ['pinned principal mismatch', [
            'result'      => 'failed principal_mismatch',
            'events'      => ['Attempting api', 'Failed api i1', 'AuthenticationFailed api sign_in:principal_mismatch i1/-/-'],
            'timebox'     => 'padded',
            'rehashed'    => false,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'no default principal' => ['no default principal', [
            'result'      => 'principal_required',
            'events'      => ['Attempting choosers', 'PrincipalChoiceRequired choosers i1/-/-'],
            'timebox'     => 'cut short',
            'rehashed'    => true,
            'reservation' => 'kept',
            'account'     => 'kept',
        ]];

        yield 'factor required' => ['factor required', [
            'result'      => 'factor_required',
            'events'      => ['Attempting api', 'AdditionalFactorRequired api i1/p1/-'],
            'timebox'     => 'cut short',
            'rehashed'    => true,
            'reservation' => 'kept',
            'account'     => 'kept',
        ]];

        yield 'success' => ['success', [
            'result' => 'signed_in',
            'events' => [
                'Attempting api',
                'DeviceCreated api i1/p1/d1',
                'SignedIn api new i1/p1/d1',
                'Validated api i1',
                'Login api i1',
                'Authenticated api i1',
                'PrincipalAssigned api i1/p1/d1',
                'DeviceAuthenticated api i1/p1/d1',
            ],
            'timebox'     => 'cut short',
            'rehashed'    => true,
            'reservation' => 'released',
            'account'     => 'released',
        ]];

        yield 'throwing Validated listener' => ['throwing Validated listener', [
            'result'      => self::THREW,
            'events'      => ['Attempting api', 'DeviceCreated api i1/p1/d1', 'SignedIn api new i1/p1/d1', 'Validated api i1'],
            'timebox'     => 'cut short',
            'rehashed'    => true,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];

        yield 'throwing Login listener' => ['throwing Login listener', [
            'result'      => self::THREW,
            'events'      => ['Attempting api', 'DeviceCreated api i1/p1/d1', 'SignedIn api new i1/p1/d1', 'Validated api i1', 'Login api i1'],
            'timebox'     => 'cut short',
            'rehashed'    => true,
            'reservation' => 'consumed',
            'account'     => 'consumed',
        ]];
    }

    /**
     * The session service's `signIn('password')` answers, reports, times,
     * rehashes and counts each case as its row says.
     *
     * @param  string  $case
     * @param  array{result: string, events: list<string>, timebox: string, rehashed: bool, reservation: string, account: string}  $row
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSignInRows')]
    public function testASignInDoesWhatItsRowSays(string $case, array $row): void
    {
        $arranged = $this->arrange($case);

        [$box, $limiter] = $this->instrument($case);

        $sessions = $this->sessions($arranged['guard']);
        $context  = $arranged['principal'] === null ? null : new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), principal: $arranged['principal']);

        $this->record($case, $arranged['subject']);

        $result = self::answerOf(static fn (): string => self::describe($sessions->signIn('password', $arranged['credentials'], $context)));

        self::assertSame($row, $this->observed($result, $arranged['subject'], $box, $limiter));
    }

    /**
     * Register the guards the cases sign in through, beside the session tests'
     * own: one over members who must choose a principal, one over machine
     * clients that allows the password method, and one over the session tests'
     * identities that does not.
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

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.providers.machine_clients', ['driver' => 'model', 'model' => MachineClient::class]);
        $config->set('auth.guards.choosers', ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
        $config->set('auth.guards.machines', ['driver' => 'jwt', 'provider' => 'machine_clients', 'audience' => ['methods' => ['password']]]);
        $config->set('auth.guards.passwordless', ['driver' => 'jwt', 'provider' => 'identities', 'audience' => ['methods' => ['sso']]]);
    }

    /**
     * Seed what the case signs in as, with an outdated password hash, and say
     * which guard it signs in through, with which credentials and pins.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $case
     * @return array{guard: string, credentials: array<string, string>, principal: ?\SineMacula\Laravel\Authentication\Contracts\Principal, device: ?\SineMacula\Laravel\Authentication\Contracts\Device, subject: \Illuminate\Database\Eloquent\Model}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function arrange(string $case): array
    {
        $subject  = $this->seedSubject($case);
        $arranged = ['guard' => 'api', 'credentials' => self::credentials(), 'principal' => null, 'device' => null];

        $arranged = match ($case) {
            'invalid password'          => [...$arranged, 'credentials' => ['email' => 'ada@example.test', 'password' => 'not the password']],
            'unknown identifier'        => [...$arranged, 'credentials' => self::credentials('nobody@example.test')],
            'method not allowed'        => [...$arranged, 'guard' => 'passwordless'],
            'machine identity'          => [...$arranged, 'guard' => 'machines', 'credentials' => self::credentials('machine@example.test')],
            'no default principal'      => [...$arranged, 'guard' => 'choosers', 'credentials' => self::credentials('chooser@example.test')],
            'pinned principal mismatch' => [...$arranged, 'principal' => $this->seedIdentity('grace@example.test')],
            'pinned device mismatch'    => [...$arranged, 'principal' => $subject, 'device' => $this->anotherIdentitysDevice()],
            default                     => $arranged,
        };

        assert($arranged['principal'] === null || $arranged['principal'] instanceof Principal);

        return [...$arranged, 'subject' => $subject];
    }

    /**
     * Seed the identity the case signs in as, with a password hash older than
     * the hasher's settings, which an admitted sign-in replaces.
     *
     * @param  string  $case
     * @return \Illuminate\Database\Eloquent\Model
     */
    private function seedSubject(string $case): Model
    {
        $subject = match ($case) {
            'machine identity'     => MachineClient::query()->create(['email' => 'machine@example.test']),
            'no default principal' => $this->seedChooser(),
            'inactive identity'    => $this->seedIdentity(active: false),
            default                => $this->seedIdentity(),
        };

        $subject->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD, ['rounds' => 5])])->save();

        return $subject;
    }

    /**
     * Bind the recording timebox and limiter the sign-in runs with, and return
     * them; give the timebox a budget a check stays inside, and set the
     * policies and limits the case needs.
     *
     * @param  string  $case
     * @return array{0: \Tests\Fixtures\Passwords\RecordingTimebox, 1: \Tests\Fixtures\Sessions\RecordingAttemptLimiter}
     */
    private function instrument(string $case): array
    {
        $box     = new RecordingTimebox;
        $limiter = new RecordingAttemptLimiter(refuse: match ($case) {
            'spent account attempts'        => static fn (AttemptSubject $subject): ?int => $subject->account === null ? null : 90,
            'identifier or IP rate limited' => static fn (AttemptSubject $subject): ?int => $subject->account === null ? 60 : null,
            default                         => null,
        });

        app()->instance(Timebox::class, $box);
        app()->instance(AttemptLimiter::class, $limiter);
        config()->set('authentication.timebox.credentials_microseconds', self::BUDGET);

        if ($case === 'factor required') {
            app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        }

        return [$box, $limiter];
    }

    /**
     * Name the identity signing in `i1` (and `p1`, as the principal it acts as)
     * and start recording, then register the case's throwing listener after the
     * recording one, so the event it throws on is recorded.
     *
     * @param  string  $case
     * @param  \Illuminate\Database\Eloquent\Model  $subject
     * @return void
     */
    private function record(string $case, Model $subject): void
    {
        $this->nameIdentities($subject);
        $this->namePrincipals($subject);
        $this->recordSequence();

        $throwsOn = match ($case) {
            'throwing Validated listener' => Validated::class,
            'throwing Login listener'     => Login::class,
            default                       => null,
        };

        if ($throwsOn === null) {
            return;
        }

        Event::listen($throwsOn, static function (): never {
            throw new \RuntimeException(self::THROWN);
        });
    }

    /**
     * The row the sign-in left: its answer, the events it dispatched, its
     * timebox, whether the subject's outdated hash was replaced, and what
     * became of its slots.
     *
     * @param  string  $result
     * @param  \Illuminate\Database\Eloquent\Model  $subject
     * @param  \Tests\Fixtures\Passwords\RecordingTimebox  $box
     * @param  \Tests\Fixtures\Sessions\RecordingAttemptLimiter  $limiter
     * @return array{result: string, events: list<string>, timebox: string, rehashed: bool, reservation: string, account: string}
     */
    private function observed(string $result, Model $subject, RecordingTimebox $box, RecordingAttemptLimiter $limiter): array
    {
        return [
            'result'      => $result,
            'events'      => $this->recordedSequence(),
            'timebox'     => self::timeboxed($box),
            'rehashed'    => $subject->newQuery()->whereKey($subject->getKey())->value('password') !== $subject->getAttribute('password'),
            'reservation' => self::disposition($limiter, false),
            'account'     => self::disposition($limiter, true),
        ];
    }

    /**
     * Whether the sign-in's one run of the timebox was padded to its budget or
     * cut short, or the timebox never ran.
     *
     * @param  \Tests\Fixtures\Passwords\RecordingTimebox  $box
     * @return string
     */
    private static function timeboxed(RecordingTimebox $box): string
    {
        return match ($box->endedEarly) {
            []      => 'not run',
            [true]  => 'cut short',
            [false] => $box->waits === [] ? 'not padded' : 'padded',
            default => 'run ' . count($box->endedEarly) . ' times',
        };
    }

    /**
     * What became of the slots the sign-in asked for, on the identifier and IP
     * limits or on the account's: `none` when it asked for none, else, for
     * each, `refused`, `released`, `kept` (held by the pending sign-in it left)
     * or `consumed` (left counted).
     *
     * @param  \Tests\Fixtures\Sessions\RecordingAttemptLimiter  $limiter
     * @param  bool  $account
     * @return string
     */
    private static function disposition(RecordingAttemptLimiter $limiter, bool $account): string
    {
        $reservations = array_filter($limiter->reservations, static fn (AttemptReservation $reservation): bool => ($reservation->subject->account !== null) === $account);
        $held         = PendingSignIn::query()->first()->attempt_windows ?? [];

        $dispositions = array_map(static fn (AttemptReservation $reservation): string => match (true) {
            !$reservation->granted()                         => 'refused',
            in_array($reservation, $limiter->released, true) => 'released',
            in_array($reservation->windows, $held, true)     => 'kept',
            default                                          => 'consumed',
        }, $reservations);

        return $dispositions === [] ? 'none' : implode(', ', $dispositions);
    }

    /**
     * Seed a member of two tenants, who has no default principal.
     *
     * @return \Tests\Integration\Fixtures\ChoosingMember
     */
    private function seedChooser(): ChoosingMember
    {
        $chooser = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $chooser->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return $chooser;
    }

    /**
     * Sign another identity in, so a device exists that the identity signing in
     * does not own.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Device
     */
    private function anotherIdentitysDevice(): Device
    {
        $this->seedIdentity('grace@example.test');

        $session = $this->sessions()->signIn('password', self::credentials('grace@example.test'))->session;

        self::assertNotNull($session);

        return $session->device;
    }

    /**
     * What the sign-in answered, or that a listener's exception ended it.
     *
     * @param  \Closure(): string  $signIn
     * @return string
     */
    private static function answerOf(\Closure $signIn): string
    {
        try {
            return $signIn();
        } catch (\RuntimeException $exception) {
            return 'threw: ' . $exception->getMessage();
        }
    }

    /**
     * A session service result as its status, then the reason and wait it
     * carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return string
     */
    private static function describe(SignInResult $result): string
    {
        return implode(' ', array_filter([
            $result->status->value,
            $result->reason?->value,
            $result->retryAfter === null ? null : (string) $result->retryAfter,
        ], static fn (?string $part): bool => $part !== null));
    }
}
