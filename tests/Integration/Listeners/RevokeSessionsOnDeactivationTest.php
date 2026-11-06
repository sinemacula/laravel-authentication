<?php

declare(strict_types = 1);

namespace Tests\Integration\Listeners;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeactivation;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithRecheckedMembers;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\InterruptingFactorPolicy;
use Tests\Integration\Fixtures\RecheckedMember;
use Tests\Integration\Fixtures\RecheckedMembership;
use Tests\TestCase;

/**
 * End-to-end tests of the optional `RevokeSessionsOnDeactivation` observer
 * against a real database, registered on both models as an application
 * registers it, for a sign-in that admitted the member before the deactivation
 * committed: once the identity or principal is reactivated, no session of that
 * sign-in works at the `auth` middleware or refreshes, whether the sign-in was
 * refused or answered inside a caller's transaction and ended at its commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnDeactivation::class)]
#[CoversClass(AdmissionRecheck::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class RevokeSessionsOnDeactivationTest extends TestCase
{
    use InteractsWithRecheckedMembers, InteractsWithSessions;

    /** @var string The guard the members sign in through. */
    private const string GUARD = 'rechecked';

    /** @var string The seeded member's email. */
    private const string EMAIL = 'rechecked@example.test';

    /**
     * Freeze the clocks, create the tables, register the routes and the
     * observer.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
        $this->createRecheckedTables();

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);

        Route::post('/refresh', static function (Request $request): array {

            $guard = app('auth')->guard(self::GUARD);

            assert($guard instanceof JwtGuard);

            return ['refreshed' => Auth::sessions($guard->getName())->refresh(
                PresentedRefreshToken::fromBody($request->string('refresh_token')->toString()),
                self::requestClient(),
            )->isRefreshed()];
        });

        RecheckedMember::observe(RevokeSessionsOnDeactivation::class);
        RecheckedMembership::observe(RevokeSessionsOnDeactivation::class);
    }

    /**
     * Release the clocks and drop the tables.
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
     * Rows of `[the deactivation made after the sign-in admitted the member,
     * before its session was written, the reactivation, the reason the
     * sign-in is refused for]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed, 1: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideDeactivationsDuringASignIn(): iterable
    {
        yield 'identity' => [
            static fn (RecheckedMember $member): bool => $member->update(['is_active' => false]),
            static fn (RecheckedMember $member): bool => $member->update(['is_active' => true]),
            FailureReason::IDENTITY_INACTIVE,
        ];
        yield 'principal' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): bool => $membership->update(['is_active' => false]),
            static fn (RecheckedMember $member, RecheckedMembership $membership): bool => $membership->update(['is_active' => true]),
            FailureReason::PRINCIPAL_INACTIVE,
        ];
    }

    /**
     * A sign-in that admitted the member before a deactivation committed, the
     * observer's revocation finding no session of it, is refused once its
     * session is written, so once the identity or principal is reactivated no
     * session of it works: the member signs in afresh.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed  $deactivate
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed  $reactivate
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeactivationsDuringASignIn')]
    public function testASignInAdmittedBeforeADeactivationNeverOutlivesTheReactivation(\Closure $deactivate, \Closure $reactivate, FailureReason $reason): void
    {
        [$member, $membership] = $this->seedRechecked(self::EMAIL);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy(static fn (): mixed => $deactivate($member, $membership)));

        $refused = Auth::sessions(self::GUARD)->signIn('password', self::credentials(self::EMAIL), self::requestContext());

        self::assertSame($reason, $refused->reason);
        self::assertNull($refused->session);

        $reactivate($member, $membership);

        $this->moveClocksTo(CarbonImmutable::now()->addMinute());

        self::assertSame(0, DB::table('authentication_sessions')->whereNull('revoked_at')->count());

        $this->bearer($this->signIn()->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * Rows of `[the deactivation made inside the sign-in's transaction after the
     * sign-in admitted the member, the reactivation, the reason the answered
     * session is revoked with]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed, 1: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed, 2: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideDeactivationsInsideASignInsTransaction(): iterable
    {
        yield 'identity' => [
            static fn (RecheckedMember $member): bool => $member->update(['is_active' => false]),
            static fn (RecheckedMember $member): bool => $member->update(['is_active' => true]),
            RevocationReason::IDENTITY_DEACTIVATED,
        ];
        yield 'principal' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): bool => $membership->update(['is_active' => false]),
            static fn (RecheckedMember $member, RecheckedMembership $membership): bool => $membership->update(['is_active' => true]),
            RevocationReason::PRINCIPAL_DEACTIVATED,
        ];
    }

    /**
     * A sign-in inside a caller's transaction that admitted the member before a
     * deactivation made in that transaction is answered with its session, which
     * is ended once the transaction commits: after the reactivation neither its
     * access token nor its refresh token works.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed  $deactivate
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership): mixed  $reactivate
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeactivationsInsideASignInsTransaction')]
    public function testASignInAnsweredInsideTheDeactivationsTransactionIsEndedAtItsCommit(\Closure $deactivate, \Closure $reactivate, RevocationReason $reason): void
    {
        [$member, $membership] = $this->seedRechecked(self::EMAIL);

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy(static fn (): mixed => $deactivate($member, $membership)));

        DB::beginTransaction();

        $answered = Auth::sessions(self::GUARD)->signIn('password', self::credentials(self::EMAIL), self::requestContext())->session;

        self::assertNotNull($answered);

        DB::commit();

        $reactivate($member, $membership);

        $this->moveClocksTo(CarbonImmutable::now()->addMinute());

        self::assertNotNull(DB::table('authentication_sessions')->where('id', $answered->record->getKey())->value('revoked_at'));
        self::assertSame($reason->value, DB::table('authentication_sessions')->where('id', $answered->record->getKey())->value('revoked_reason'));

        $this->bearer($answered->tokens->accessToken->reveal())->assertUnauthorized();
        $this->postJson('/refresh', ['refresh_token' => $answered->tokens->refreshToken?->reveal()])->assertOk()->assertExactJson(['refreshed' => false]);
    }

    /**
     * Register the guards.
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

        $config->set('auth.defaults.guard', self::GUARD);
    }

    /**
     * Sign the member in afresh.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = Auth::sessions(self::GUARD)->signIn('password', self::credentials(self::EMAIL), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function moveClocksTo(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
