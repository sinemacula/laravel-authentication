<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasskeyAdded;
use SineMacula\Laravel\Authentication\Events\PasskeyUsed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\PasskeyChallenge;
use SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationFailure;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;
use SineMacula\Laravel\Authentication\Passkeys\RelyingParty;
use Tests\Concerns\InteractsWithFoldingCollations;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for the challenges of passkey ceremonies: what an issued
 * challenge records, the conditions only one answer can use it up under, the
 * exact owner among them whatever the collation counts as equal, and the
 * configured lifetime.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChallenges::class)]
final class PasskeyChallengesTest extends TestCase
{
    use InteractsWithFoldingCollations, InteractsWithPasskeys, InteractsWithSessions;

    /** @var string The key of an identity keyed by name. */
    private const string NAMED = 'alice';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
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

        $this->createSessionTables();
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An issued challenge records its ceremony, guard, relying party, owner and
     * options, and expires after the lifetime; what the client is handed names
     * it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIssuedChallengeRecordsItsCeremony(): void
    {
        $identity = $this->seedIdentity();
        $issued   = self::challenges()->issue(ChallengePurpose::FACTOR, self::rp('api'), $identity, ['challenge' => 'abc'], $this->now);
        $stored   = PasskeyChallenge::query()->sole();

        self::assertSame([$stored->id, ['challenge' => 'abc']], [$issued->challengeId, $issued->options]);
        self::assertTrue($issued->expiresAt->equalTo($this->now->addSeconds(300)));
        self::assertSame(['factor', 'api', self::RP_ID], [$stored->purpose, $stored->guard, $stored->rp_id]);
        self::assertSame([IntegrationIdentity::class, (string) $identity->id], [$stored->authenticatable_type, $stored->authenticatable_id]);
        self::assertSame(['challenge' => 'abc'], $stored->options);
        self::assertTrue($stored->expires_at->equalTo($this->now->addSeconds(300)));
    }

    /**
     * A challenge is used up by the first answer that matches it, which gets
     * its options back; a second answer gets nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChallengeIsUsedUpOnce(): void
    {
        $identity = $this->seedIdentity();
        $issued   = self::challenges()->issue(ChallengePurpose::REGISTER, self::rp('api'), $identity, ['challenge' => 'abc'], $this->now);

        self::assertSame(['challenge' => 'abc'], self::challenges()->consume($issued->challengeId, ChallengePurpose::REGISTER, self::rp('api'), $identity, $this->now));
        self::assertNull(self::challenges()->consume($issued->challengeId, ChallengePurpose::REGISTER, self::rp('api'), $identity, $this->now));
        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * A usernameless challenge is used up by an answer that names no owner.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAUsernamelessChallengeIsUsedUpWithoutAnOwner(): void
    {
        $issued = self::challenges()->issue(ChallengePurpose::SIGN_IN, self::rp('api'), null, ['challenge' => 'abc'], $this->now);

        self::assertSame(['challenge' => 'abc'], self::challenges()->consume($issued->challengeId, ChallengePurpose::SIGN_IN, self::rp('api'), null, $this->now));
    }

    /**
     * Rows of `[purpose, guard, owner, seconds later, id]`: answers that do not
     * match a registration challenge of `api` for the identity (`owner` is
     * `identity`, `none`, `another` identity or a `member` of another class
     * under the same key; `id` replaces the challenge's when given).
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose, 1: string, 2: string, 3: int, 4: ?string}>
     */
    public static function provideMismatchedAnswers(): iterable
    {
        yield from [
            'another ceremony'     => [ChallengePurpose::FACTOR, 'api', 'identity', 0, null],
            'another guard'        => [ChallengePurpose::REGISTER, 'admin', 'identity', 0, null],
            'no owner'             => [ChallengePurpose::REGISTER, 'api', 'none', 0, null],
            'another owner'        => [ChallengePurpose::REGISTER, 'api', 'another', 0, null],
            'another owner class'  => [ChallengePurpose::REGISTER, 'api', 'member', 0, null],
            'at its expiry'        => [ChallengePurpose::REGISTER, 'api', 'identity', 300, null],
            'an unknown challenge' => [ChallengePurpose::REGISTER, 'api', 'identity', 0, '0192f6b2-0000-7000-8000-000000000001'],
        ];
    }

    /**
     * An answer for another ceremony, guard or owner, or at the challenge's
     * expiry, gets nothing and leaves the challenge for its own answer, which
     * the second before the expiry still gets.
     *
     * @param  \SineMacula\Laravel\Authentication\Passkeys\Enums\ChallengePurpose  $purpose
     * @param  string  $guard
     * @param  string  $owner
     * @param  int  $later
     * @param  ?string  $id
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMismatchedAnswers')]
    public function testAnAnswerThatDoesNotMatchGetsNothing(ChallengePurpose $purpose, string $guard, string $owner, int $later, ?string $id): void
    {
        $identity = $this->seedIdentity();
        $issued   = self::challenges()->issue(ChallengePurpose::REGISTER, self::rp('api'), $identity, ['challenge' => 'abc'], $this->now);
        $answerer = match ($owner) {
            'identity' => $identity,
            'another'  => $this->seedIdentity('grace@example.test'),
            'member'   => $this->seedMember()[0],
            default    => null,
        };

        self::assertNull(self::challenges()->consume($id ?? $issued->challengeId, $purpose, self::rp($guard), $answerer, $this->now->addSeconds($later)));
        self::assertSame(1, PasskeyChallenge::query()->count());
        $justInTime = self::challenges()->consume($issued->challengeId, ChallengePurpose::REGISTER, self::rp('api'), $identity, $this->now->addSeconds(299));

        self::assertSame(['challenge' => 'abc'], $justInTime);
    }

    /**
     * An id that names no challenge is answered after one read, with nothing
     * deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownChallengeCostsOneRead(): void
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = $query->sql;
        });

        self::assertNull(self::challenges()->consume('0192f6b2-0000-7000-8000-000000000001', ChallengePurpose::SIGN_IN, self::rp('api'), null, $this->now));
        self::assertCount(1, $queries);
        self::assertStringStartsWith('select', $queries[0]);
    }

    /**
     * A challenge issued for a relying party the guard no longer has gets
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChallengeOfAnotherRelyingPartyGetsNothing(): void
    {
        $issued = self::challenges()->issue(ChallengePurpose::SIGN_IN, self::rp('api'), null, [], $this->now);

        config()->set('auth.guards.api.passkeys', ['id' => 'app.example.test']);

        self::assertNull(self::challenges()->consume($issued->challengeId, ChallengePurpose::SIGN_IN, self::rp('api'), null, $this->now));
        self::assertSame(1, PasskeyChallenge::query()->count());
    }

    /**
     * An id that is not a UUID names no challenge, and no query is made for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdThatIsNotAUuidIsRefusedWithoutAQuery(): void
    {
        $queries = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertNull(self::challenges()->consume('challenge', ChallengePurpose::SIGN_IN, self::rp('api'), null, $this->now));
        self::assertSame(0, $queries);
    }

    /**
     * Rows of `[lifetime, seconds]`: lifetimes accepted, as an integer or a
     * digit string, and the default when none is configured.
     *
     * @return iterable<string, array{0: mixed, 1: int}>
     */
    public static function provideLifetimes(): iterable
    {
        yield from [
            'the shortest'   => [30, 30],
            'the longest'    => ['600', 600],
            'a digit string' => ['120', 120],
        ];
    }

    /**
     * A challenge lives the configured lifetime.
     *
     * @param  mixed  $lifetime
     * @param  int  $seconds
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLifetimes')]
    public function testAChallengeLivesTheConfiguredLifetime(mixed $lifetime, int $seconds): void
    {
        config()->set('authentication.passkeys.challenge_ttl_seconds', $lifetime);

        self::assertSame($seconds, self::challenges()->ttlSeconds());
        self::assertTrue(self::challenges()->issue(ChallengePurpose::SIGN_IN, self::rp('api'), null, [], $this->now)->expiresAt->equalTo($this->now->addSeconds($seconds)));
    }

    /**
     * Without a configured lifetime, a challenge lives five minutes.
     *
     * @return void
     */
    public function testTheDefaultLifetimeIsFiveMinutes(): void
    {
        config()->set('authentication.passkeys', []);

        self::assertSame(300, self::challenges()->ttlSeconds());
    }

    /**
     * Rows of `[lifetime]`: lifetimes refused.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideInvalidLifetimes(): iterable
    {
        yield from [
            'too short'       => [29],
            'too long'        => [601],
            'zero'            => [0],
            'negative'        => [-300],
            'a float'         => [300.0],
            'a word'          => ['five minutes'],
            'a padded string' => [' 300'],
            'a leading zero'  => ['0300'],
            'too many digits' => ['1000000'],
            'trailing text'   => ['300s'],
            'a trailing line' => ["300\n"],
            'null'            => [null],
        ];
    }

    /**
     * A lifetime out of range or of another type fails closed, naming the key,
     * before anything is stored.
     *
     * @param  mixed  $lifetime
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideInvalidLifetimes')]
    public function testAnInvalidLifetimeFailsClosed(mixed $lifetime): void
    {
        config()->set('authentication.passkeys.challenge_ttl_seconds', $lifetime);

        try {
            self::challenges()->issue(ChallengePurpose::SIGN_IN, self::rp('api'), null, [], $this->now);

            self::fail('Expected the lifetime to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('authentication.passkeys.challenge_ttl_seconds must be an integer from 30 to 600 seconds.', $exception->getMessage());
        }

        self::assertSame(0, PasskeyChallenge::query()->count());
    }

    /**
     * With the owner columns under a collation that counts distinct keys as
     * equal, an identity whose key differs from the owner's only in case or
     * accent cannot answer the owner's registration challenge, which it leaves
     * unused, so the owner still registers with it.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherKeyTheCollationCountsAsEqualCannotAnswerARegistrationChallenge(string $folded): void
    {
        self::foldColumns('passkey_challenges', ['authenticatable_type', 'authenticatable_id'], nullable: true);

        $owner    = self::namedIdentity(self::NAMED);
        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->registrationOptions($owner, self::USER_NAME);
        $answer   = $this->authenticator()->create($options->options);

        self::assertColumnFolds('passkey_challenges', 'authenticatable_id', $folded);

        Event::fake([PasskeyAdded::class]);

        self::assertSame(PasskeyRegistrationFailure::CHALLENGE_INVALID, $passkeys->register(self::namedIdentity($folded), $options->challengeId, $answer));
        self::assertSame(1, DB::table('passkey_challenges')->count());
        self::assertSame(0, DB::table('passkeys')->count());

        Event::assertNotDispatched(PasskeyAdded::class);

        self::assertInstanceOf(PasskeySummary::class, $passkeys->register($owner, $options->challengeId, $answer));
        self::assertSame(self::NAMED, DB::table('passkeys')->value('authenticatable_id'));
    }

    /**
     * With the owner columns under a collation that counts distinct keys as
     * equal, an identity whose key differs from the owner's only in case or
     * accent cannot answer the owner's factor challenge with the owner's
     * passkey, which it leaves unused, so the owner still verifies the factor
     * with it.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAnotherKeyTheCollationCountsAsEqualCannotAnswerAFactorChallenge(string $folded): void
    {
        self::foldColumns('passkey_challenges', ['authenticatable_type', 'authenticatable_id'], nullable: true);

        $owner = self::namedIdentity(self::NAMED);

        $this->registerPasskey($owner);

        $passkeys = Auth::passkeys('api');
        $options  = $passkeys->factorOptions($owner);
        $answer   = $this->authenticator()->get($options->options);

        self::assertColumnFolds('passkey_challenges', 'authenticatable_id', $folded);

        Event::fake([PasskeyUsed::class]);

        self::assertSame(FailureReason::PASSKEY_CHALLENGE_INVALID, $passkeys->verifyFactor(self::namedIdentity($folded), $options->challengeId, $answer));
        self::assertSame(1, DB::table('passkey_challenges')->count());

        Event::assertNotDispatched(PasskeyUsed::class);

        self::assertNull($passkeys->verifyFactor($owner, $options->challengeId, $answer));
    }

    /**
     * Configure the guards and their relying party.
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
        self::configurePasskeys($config);
    }

    /**
     * The challenge store over the current configuration.
     *
     * @return \SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges
     */
    private static function challenges(): PasskeyChallenges
    {
        return new PasskeyChallenges(app(ConfigRepository::class));
    }

    /**
     * The guard's relying party.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Passkeys\RelyingParty
     */
    private static function rp(string $guard): RelyingParty
    {
        return RelyingParty::forGuard($guard, app(ConfigRepository::class));
    }
}
