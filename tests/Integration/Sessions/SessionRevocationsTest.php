<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\TestCase;

/**
 * Integration tests of a guard's logout everywhere for an identity with a
 * tokens-valid-after cutoff.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevocations::class)]
final class SessionRevocationsTest extends TestCase
{
    /** @var string The identity's password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var \Carbon\CarbonImmutable The time every revocation happens at. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Keeping a binding's session-less token leaves the cutoff.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeepingASessionlessTokenLeavesTheCutoff(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn($identity);

        $guard = $this->bearing($this->tokens()->issueAccessToken($identity, $identity, null, null)->reveal());

        $this->moveClocksTo($this->now->addMinute());

        self::assertSame(1, $this->revocationsOf($guard)->signOutEverywhere($guard, true));
        self::assertNull($identity->fresh()?->getTokensValidAfter());
        self::assertSame('signed_out_everywhere', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * Keeping a binding's session still moves the cutoff.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeepingASessionStillMovesTheCutoff(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->bearing($this->signIn($identity));

        $this->signIn($identity);
        $this->moveClocksTo($this->now->addMinute());

        self::assertSame(1, $this->revocationsOf($guard)->signOutEverywhere($guard, true));
        self::assertSame($this->now->toDateTimeString(), $identity->fresh()?->getTokensValidAfter()?->toDateTimeString());
        self::assertSame(1, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
    }

    /**
     * Without the keep, a binding's session-less token ends as the cutoff
     * moves.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNotKeepingASessionlessTokenMovesTheCutoff(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->bearing($this->tokens()->issueAccessToken($identity, $identity, null, null)->reveal());

        $this->moveClocksTo($this->now->addMinute());

        self::assertSame(0, $this->revocationsOf($guard)->signOutEverywhere($guard, false));
        self::assertSame($this->now->toDateTimeString(), $identity->fresh()?->getTokensValidAfter()?->toDateTimeString());
    }

    /**
     * Rows of `[logout everywhere]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \SineMacula\Laravel\Authentication\Guards\JwtGuard, \Tests\Integration\Fixtures\CutoffIdentity): int}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideLogoutsEverywhere(): iterable
    {
        yield 'the identity\'s sessions' => [
            static fn (SessionRevocations $service, JwtGuard $guard, CutoffIdentity $identity): int => $service->revokeSessions($identity, RevocationReason::REVOKED),
        ];

        yield 'the principal\'s sessions' => [
            static fn (SessionRevocations $service, JwtGuard $guard, CutoffIdentity $identity): int => $service->revokePrincipalSessions($identity, RevocationReason::REVOKED),
        ];

        yield 'signing out everywhere' => [
            static fn (SessionRevocations $service, JwtGuard $guard): int => $service->signOutEverywhere($guard, false),
        ];
    }

    /**
     * A logout everywhere rolls back with the caller's transaction.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \SineMacula\Laravel\Authentication\Guards\JwtGuard, \Tests\Integration\Fixtures\CutoffIdentity): int  $logout
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLogoutsEverywhere')]
    public function testALogoutEverywhereRollsBackWithTheCallersTransaction(\Closure $logout): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->bearing($this->signIn($identity));
        $events   = $this->recordRevocations();

        $this->signIn($identity);
        $this->moveClocksTo($this->now->addMinute());

        DB::beginTransaction();

        $identity->forceFill(['email' => 'grace@example.test'])->save();

        self::assertSame(2, $logout($this->revocationsOf($guard), $guard, $identity));

        DB::rollBack();

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertSame('ada@example.test', $stored->email);
        self::assertNull($stored->getTokensValidAfter());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame([], $events->getArrayCopy());
    }

    /**
     * A logout everywhere commits with the caller's transaction and reports
     * once after the commit.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionRevocations, \SineMacula\Laravel\Authentication\Guards\JwtGuard, \Tests\Integration\Fixtures\CutoffIdentity): int  $logout
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideLogoutsEverywhere')]
    public function testALogoutEverywhereCommitsWithTheCallersTransaction(\Closure $logout): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->bearing($this->signIn($identity));
        $events   = $this->recordRevocations();

        $this->signIn($identity);
        $this->moveClocksTo($this->now->addMinute());

        DB::transaction(function () use ($logout, $guard, $identity, $events): void {

            $identity->forceFill(['email' => 'grace@example.test'])->save();

            self::assertSame(2, $logout($this->revocationsOf($guard), $guard, $identity));
            self::assertSame([], $events->getArrayCopy());
        });

        $stored = $identity->fresh();

        self::assertNotNull($stored);
        self::assertSame('grace@example.test', $stored->email);
        self::assertSame($this->now->toDateTimeString(), $stored->getTokensValidAfter()?->toDateTimeString());
        self::assertSame(2, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $events->getArrayCopy());
    }

    /**
     * Configure the `api` guard over the identities that record a cutoff.
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

        $config->set('auth.providers.cutoff', ['driver' => 'model', 'model' => CutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'cutoff', 'application' => ['methods' => ['password']]]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity that records no cutoff yet.
     *
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function seedIdentity(): CutoffIdentity
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => 'ada@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        return $identity;
    }

    /**
     * Sign the identity in and return the session's access token.
     *
     * @param  \Tests\Integration\Fixtures\CutoffIdentity  $identity
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(CutoffIdentity $identity): string
    {
        Auth::forgetGuards();

        $session = Auth::sessions('api')->signIn('password', ['email' => $identity->email, 'password' => self::PASSWORD], self::requestContext())->session;

        self::assertNotNull($session);

        return $session->tokens->accessToken->reveal();
    }

    /**
     * Record the class of every revocation and logout everywhere reported, in
     * order.
     *
     * @return \ArrayObject<int, class-string>
     */
    private function recordRevocations(): \ArrayObject
    {
        /** @var \ArrayObject<int, class-string> $events */
        $events = new \ArrayObject;

        Event::listen([SessionRevoked::class, SignedOutEverywhere::class], static function (object $event) use ($events): void {
            $events->append($event::class);
        });

        return $events;
    }

    /**
     * A fresh, unresolved `api` guard for a request bearing the token.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearing(string $token): JwtGuard
    {
        Auth::forgetGuards();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard->setRequest(Request::create('/logout-everywhere', 'POST', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]));
    }

    /**
     * The session revocations on the guard's context.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionRevocations
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function revocationsOf(JwtGuard $guard): SessionRevocations
    {
        return SessionRevocations::forContext($guard->context(), app());
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * Move every clock to the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function moveClocksTo(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
