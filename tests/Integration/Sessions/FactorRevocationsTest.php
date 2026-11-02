<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * Integration tests of the factor package's mandatory triggers, and of a
 * removed first-factor credential, inside the factor package's own transaction
 * on the storage connection: everything they write (the revocations, the voided
 * proofs, the current session's return to pending) commits or rolls back with
 * the factor package's change, nothing is reported until it commits, and the
 * guard forgets the current session only then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRevocations::class)]
final class FactorRevocationsTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Freeze the clocks, create the tables and ask every sign-in for a further
     * factor.
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

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
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
     * Rows of `[the trigger, the sessions it revokes, whether the current
     * session returns to pending, the events it reports]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Session): int, 1: int, 2: bool, 3: list<class-string>}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideTriggers(): iterable
    {
        yield 'a factor removed' => [
            static fn (Identity $identity, Session $current): int => Auth::sessions('api')->factorRemoved($identity, 'factor-a', $current)->revoked,
            1,
            true,
            [SessionRevoked::class, SignedOutEverywhere::class, SessionReturnedToPending::class],
        ];

        yield 'the factors reset' => [
            static fn (Identity $identity): int => Auth::sessions('api')->factorReset($identity),
            2,
            false,
            [SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class],
        ];

        yield 'a credential removed' => [
            static fn (Identity $identity, Session $current): int => Auth::sessions('api')->credentialRemoved($identity, $current),
            1,
            false,
            [SessionRevoked::class, SignedOutEverywhere::class],
        ];
    }

    /**
     * Inside the factor package's transaction that rolls back, the trigger
     * leaves every session as it was, voids nothing, reports nothing, and the
     * guard stays bound to the current session.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Session): int  $trigger
     * @param  int  $revoked
     * @param  bool  $returns
     * @param  list<class-string>  $events
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTriggers')]
    public function testATriggerRollsBackWithTheFactorPackagesTransaction(\Closure $trigger, int $revoked, bool $returns, array $events): void
    {
        unset($returns, $events);

        $this->seedIdentity();

        $this->satisfied('factor-a');

        $current  = $this->satisfied('factor-a');
        $guard    = $this->boundGuard($current);
        $recorded = $this->recordTriggerEvents();

        DB::beginTransaction();

        self::assertSame($revoked, $trigger($current->identity, $current->record));

        DB::rollBack();

        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame(2, DB::table('authentication_sessions')->where('status', 'active')->count());
        self::assertSame(0, DB::table('authentication_proofs')->whereNotNull('voided_at')->count());
        self::assertSame([], $recorded->getArrayCopy());
        self::assertSame($current->record->getKey(), $guard->session()?->getSessionIdentifier());
    }

    /**
     * Inside the factor package's transaction that commits, the trigger's
     * writes commit with the factor package's own, each event is reported once
     * after the commit and none before, and a current session taken back to
     * pending has its proofs with the factor voided and the guard bound to it
     * forgotten.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity, \SineMacula\Laravel\Authentication\Contracts\Session): int  $trigger
     * @param  int  $revoked
     * @param  bool  $returns
     * @param  list<class-string>  $events
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTriggers')]
    public function testATriggerCommitsWithTheFactorPackagesTransaction(\Closure $trigger, int $revoked, bool $returns, array $events): void
    {
        $this->seedIdentity();

        $this->satisfied('factor-a');

        $current  = $this->satisfied('factor-a');
        $guard    = $this->boundGuard($current);
        $recorded = $this->recordTriggerEvents();

        DB::transaction(function () use ($trigger, $current, $revoked, $recorded): void {

            DB::table('integration_identities')->update(['email' => 'grace@example.test']);

            self::assertSame($revoked, $trigger($current->identity, $current->record));
            self::assertSame([], $recorded->getArrayCopy());
        });

        self::assertSame('grace@example.test', DB::table('integration_identities')->value('email'));
        self::assertSame($revoked, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame($returns ? 'pending' : null, DB::table('authentication_sessions')->where('status', 'pending')->value('status'));
        self::assertSame($returns ? 1 : 0, DB::table('authentication_proofs')->whereNotNull('voided_at')->count());
        self::assertSame($events, $recorded->getArrayCopy());
        self::assertSame($returns ? null : $current->record->getKey(), $guard->session()?->getSessionIdentifier());
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
     * A session of the seeded identity that signed in pending a further factor
     * and was activated with the factor given.
     *
     * @param  string  $factor
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function satisfied(string $factor): SignedInSession
    {
        $pending = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $proof = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            $factor,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($pending->pending->identity, 'api', $pending->pending->id, Purpose::SIGN_IN),
        );

        $session = Auth::sessions('api')->satisfy($pending->credential, $proof)->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The `api` guard, resolved afresh and bound to the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function boundGuard(SignedInSession $signedIn): JwtGuard
    {
        $guard = $this->freshGuard();

        $guard->login($signedIn->identity, $signedIn->principal, $signedIn->record);

        return $guard;
    }

    /**
     * Record the class of every revocation, logout everywhere and return to
     * pending reported from now on, in order.
     *
     * @return \ArrayObject<int, class-string>
     */
    private function recordTriggerEvents(): \ArrayObject
    {
        /** @var \ArrayObject<int, class-string> $events */
        $events = new \ArrayObject;

        Event::listen([SessionRevoked::class, SignedOutEverywhere::class, SessionReturnedToPending::class], static function (object $event) use ($events): void {
            $events->append($event::class);
        });

        return $events;
    }
}
