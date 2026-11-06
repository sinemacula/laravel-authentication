<?php

declare(strict_types = 1);

namespace Tests\Integration\Listeners;

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
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeletion;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Fixtures\Sessions\InterruptingFactorPolicy;
use Tests\Integration\Fixtures\SoftDeletingMember;
use Tests\Integration\Fixtures\SoftDeletingMembership;
use Tests\TestCase;

/**
 * End-to-end tests of the optional `RevokeSessionsOnDeletion` observer against
 * a real database, registered on both models as an application registers it: a
 * soft-deleted identity's or principal's session stays refused at the `auth`
 * middleware and unrefreshable after a restore, a session-less token issued
 * before the soft delete stays refused through the cutoff it moved, and a
 * database cascade that removes the principals with their identity needs no
 * event of theirs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnDeletion::class)]
#[CoversClass(AdmissionRecheck::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class RevokeSessionsOnDeletionTest extends TestCase
{
    /** @var string The members' password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var list<\SineMacula\Laravel\Authentication\Events\Enums\FailureReason> The reasons of the refused tokens. */
    private array $reasons = [];

    /**
     * Freeze the clocks, create the tables, record the refusals, register the
     * routes and the observer.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        Schema::create('soft_deleting_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        Schema::create('soft_deleting_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
            $blueprint->softDeletes();

            $blueprint->foreign('identity_id')->references('id')->on('soft_deleting_members')->cascadeOnDelete();
        });

        Schema::enableForeignKeyConstraints();

        Event::listen(AuthenticationFailed::class, function (AuthenticationFailed $event): void {
            $this->reasons[] = $event->reason;
        });

        Route::middleware('auth:members')->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);

        Route::post('/refresh', static function (Request $request): array {

            $guard = app('auth')->guard('members');

            assert($guard instanceof JwtGuard);

            return ['refreshed' => Auth::sessions($guard->getName())->refresh(
                PresentedRefreshToken::fromBody($request->string('refresh_token')->toString()),
                self::requestClient(),
            )->isRefreshed()];
        });

        SoftDeletingMember::observe(RevokeSessionsOnDeletion::class);
        SoftDeletingMembership::observe(RevokeSessionsOnDeletion::class);
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('soft_deleting_memberships');
        Schema::dropIfExists('soft_deleting_members');

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A soft-deleted identity's session is refused, and stays refused as
     * revoked once the identity is restored; a force delete afterwards revokes
     * nothing more.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASoftDeletedIdentitysSessionStaysEndedBeyondARestore(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signIn();

        $member->delete();

        $this->assertSessionEnded($session);

        $member->restore(); // @phpstan-ignore staticMethod.dynamicCall

        $this->reasons = [];

        $this->assertSessionEnded($session);

        self::assertSame(FailureReason::SESSION_REVOKED, $this->reasons[0] ?? null);

        $revoked = [];

        Event::listen(SessionRevoked::class, static function (SessionRevoked $event) use (&$revoked): void {
            $revoked[] = $event;
        });

        $member->forceDelete();

        self::assertSame([], $revoked);
        self::assertSame('identity_deleted', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * After a soft delete and a restore, a fresh sign-in works, and a force
     * delete then ends that session too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAForceDeleteEndsASessionStartedAfterARestore(): void
    {
        [$member] = $this->seedMember();

        $earlier = $this->signIn();

        $member->delete();
        $member->restore(); // @phpstan-ignore staticMethod.dynamicCall

        $later = $this->signIn();

        $this->bearer($later->tokens->accessToken->reveal())->assertOk();

        $member->forceDelete();

        $this->assertSessionEnded($later);

        $ended = [$earlier->record->getSessionIdentifier(), $later->record->getSessionIdentifier()];

        self::assertSame(['identity_deleted', 'identity_deleted'], DB::table('authentication_sessions')->whereIn('id', $ended)->pluck('revoked_reason')->all());
    }

    /**
     * A soft-deleted principal's session stays ended, as revoked, once the
     * principal is restored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASoftDeletedPrincipalsSessionStaysEndedBeyondARestore(): void
    {
        [, $membership] = $this->seedMember();

        $session = $this->signIn();

        $membership->delete();
        $membership->restore(); // @phpstan-ignore staticMethod.dynamicCall

        $this->reasons = [];

        $this->assertSessionEnded($session);

        self::assertSame(FailureReason::SESSION_REVOKED, $this->reasons[0] ?? null);
        self::assertSame('principal_deleted', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * Rows of `[the soft delete made after the sign-in admitted the member,
     * before its session was written, the restore, the reason the sign-in is
     * refused for]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\SoftDeletingMember, \Tests\Integration\Fixtures\SoftDeletingMembership): mixed, 1: \Closure(\Tests\Integration\Fixtures\SoftDeletingMember, \Tests\Integration\Fixtures\SoftDeletingMembership): mixed, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideDeletionsDuringASignIn(): iterable
    {
        yield 'identity' => [
            static fn (SoftDeletingMember $member): ?bool => $member->delete(),
            static fn (SoftDeletingMember $member): bool => $member->restore(), // @phpstan-ignore staticMethod.dynamicCall
            FailureReason::IDENTITY_UNKNOWN,
        ];
        yield 'principal' => [
            static fn (SoftDeletingMember $member, SoftDeletingMembership $membership): ?bool => $membership->delete(),
            static fn (SoftDeletingMember $member, SoftDeletingMembership $membership): bool => $membership->restore(), // @phpstan-ignore staticMethod.dynamicCall
            FailureReason::PRINCIPAL_UNRESOLVED,
        ];
    }

    /**
     * A sign-in that admitted the member before a soft delete committed, the
     * observer's revocation finding no session of it, is refused once its
     * session is written, so once the identity or principal is restored no
     * session of it works: the member signs in afresh.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\SoftDeletingMember, \Tests\Integration\Fixtures\SoftDeletingMembership): mixed  $delete
     * @param  \Closure(\Tests\Integration\Fixtures\SoftDeletingMember, \Tests\Integration\Fixtures\SoftDeletingMembership): mixed  $restore
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDeletionsDuringASignIn')]
    public function testASignInAdmittedBeforeASoftDeleteNeverOutlivesTheRestore(\Closure $delete, \Closure $restore, FailureReason $reason): void
    {
        [$member, $membership] = $this->seedMember();

        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy(static fn (): mixed => $delete($member, $membership)));

        $refused = Auth::sessions('members')->signIn('password', self::credentials(), self::requestContext());

        self::assertSame($reason, $refused->reason);

        $restore($member, $membership);

        self::assertSame(0, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        $this->bearer($this->signIn()->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * Deleting the identity removes its memberships by a database cascade,
     * which fires no event of theirs; the identity's own revocation ends every
     * session, those acting as each membership included, and reports each with
     * the principal it acted as although that row is gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACascadeFromTheIdentityNeedsNoEventOfItsPrincipals(): void
    {
        [$member, $first] = $this->seedMember();

        $firstSession = $this->signIn();
        $second       = SoftDeletingMembership::query()->create(['identity_id' => $member->id]);
        $result       = Auth::sessions('members')->signIn('password', self::credentials(), SignInContext::fromRequest(request(), principal: $second));

        self::assertNotNull($result->session);

        $revoked = [];

        Event::listen(SessionRevoked::class, static function (SessionRevoked $event) use (&$revoked): void {
            $revoked[] = [$event->context->sessionId, $event->reason->value, $event->context->principalType, $event->context->principalId];
        });

        $member->forceDelete();

        self::assertSame(0, DB::table('soft_deleting_memberships')->count());
        self::assertEqualsCanonicalizing([
            [IdentifierCoercion::stringify($firstSession->record->getSessionIdentifier()), 'identity_deleted', SoftDeletingMembership::class, (string) $first->id],
            [IdentifierCoercion::stringify($result->session->record->getSessionIdentifier()), 'identity_deleted', SoftDeletingMembership::class, (string) $second->id],
        ], $revoked);

        $this->assertSessionEnded($firstSession);
        $this->assertSessionEnded($result->session);
    }

    /**
     * A token issued without a session before the identity's soft delete stays
     * refused after its restore, through the identity's cutoff the soft delete
     * moved; one issued afterwards works.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentitysSoftDeleteCutsOffItsSessionlessTokens(): void
    {
        [$member, $membership] = $this->seedMember();

        $earlier = $this->tokens()->issueAccessToken($member, $membership, null, null)->reveal();

        $this->bearer($earlier)->assertOk();
        $this->moveClocksTo(CarbonImmutable::now()->addMinute());

        $member->delete();
        $member->restore(); // @phpstan-ignore staticMethod.dynamicCall

        $this->assertCutOff($earlier, $member, $membership);
    }

    /**
     * A token issued without a session before the principal's soft delete stays
     * refused after its restore, through the principal's cutoff the soft delete
     * moved; one issued afterwards works.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsSoftDeleteCutsOffItsSessionlessTokens(): void
    {
        [$member, $membership] = $this->seedMember();

        $earlier = $this->tokens()->issueAccessToken($member, $membership, null, null)->reveal();

        $this->bearer($earlier)->assertOk();
        $this->moveClocksTo(CarbonImmutable::now()->addMinute());

        $membership->delete();
        $membership->restore(); // @phpstan-ignore staticMethod.dynamicCall

        self::assertNull($member->fresh()?->getTokensValidAfter());

        $this->assertCutOff($earlier, $member, $membership);
    }

    /**
     * Register the `members` guard over the soft-deleting members, as the
     * default guard.
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

        $config->set('auth.providers.members', ['driver' => 'model', 'model' => SoftDeletingMember::class]);
        $config->set('auth.guards.members', ['driver' => 'jwt', 'provider' => 'members', 'application' => ['methods' => ['password']]]);
        $config->set('auth.defaults.guard', 'members');
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist a member with one membership.
     *
     * @return array{0: \Tests\Integration\Fixtures\SoftDeletingMember, 1: \Tests\Integration\Fixtures\SoftDeletingMembership}
     */
    private function seedMember(): array
    {
        $member = SoftDeletingMember::query()->create(['email' => 'member@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        $membership = SoftDeletingMembership::query()->create(['identity_id' => $member->id]);

        return [$member, $membership];
    }

    /**
     * Sign the member in, check its access token works, and move the clocks a
     * minute on.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = Auth::sessions('members')->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
        $this->moveClocksTo(CarbonImmutable::now()->addMinute());

        return $session;
    }

    /**
     * Assert the token issued without a session is refused as issued before the
     * cutoff, and that one issued in the next second works.
     *
     * @param  string  $token
     * @param  \Tests\Integration\Fixtures\SoftDeletingMember  $member
     * @param  \Tests\Integration\Fixtures\SoftDeletingMembership  $membership
     * @return void
     *
     * @throws \Random\RandomException
     */
    private function assertCutOff(#[\SensitiveParameter] string $token, SoftDeletingMember $member, SoftDeletingMembership $membership): void
    {
        $this->reasons = [];

        $this->bearer($token)->assertUnauthorized();

        self::assertSame([FailureReason::ISSUED_BEFORE_CUTOFF], $this->reasons);

        $this->moveClocksTo(CarbonImmutable::now()->addSecond());

        $this->bearer($this->tokens()->issueAccessToken($member, $membership, null, null)->reveal())->assertOk();
    }

    /**
     * Assert the session's access token is refused at the `auth` middleware and
     * its refresh token refreshes nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     */
    private function assertSessionEnded(SignedInSession $session): void
    {
        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

        $this->postJson('/refresh', ['refresh_token' => $session->tokens->refreshToken?->reveal()])->assertOk()->assertExactJson(['refreshed' => false]);
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
     * The `members` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('members');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * The member's password credentials.
     *
     * @return array<string, string>
     */
    private static function credentials(): array
    {
        return ['email' => 'member@example.test', 'password' => self::PASSWORD];
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
