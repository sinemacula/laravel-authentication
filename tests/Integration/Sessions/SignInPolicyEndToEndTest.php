<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\InteractsWithTypedPrincipals;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\Integration\Fixtures\VerifiableStaffIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of signing in and refreshing through the bindings the
 * package ships, configured per guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(GuardApplicationPolicy::class)]
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(VerificationLinks::class)]
final class SignInPolicyEndToEndTest extends TestCase
{
    use InteractsWithProofs, InteractsWithRateLimits, InteractsWithSessions, InteractsWithTypedPrincipals, InteractsWithVerifiableIdentities;

    /** @var int Access lifetime of the `members` guard, in minutes. */
    private const int MEMBERS_ACCESS_MINUTES = 2;

    /** @var int Idle lifetime of a `members` session, in minutes. */
    private const int MEMBERS_IDLE_MINUTES = 60;

    /** @var int Absolute lifetime of a `members` session, in minutes. */
    private const int MEMBERS_ABSOLUTE_MINUTES = 1440;

    /**
     * Freeze the clocks twenty seconds into a minute, create the tables and add
     * the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 5, 1, 9, 0, 20);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        self::createVerifiableIdentitiesTable();

        self::createTypedPrincipalTables();

        Route::middleware('auth:members')->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);

        Route::post('/refresh', static function (Request $request): array {

            $result = Auth::sessions('members')->refresh(PresentedRefreshToken::fromBody($request->string('refresh_token')->toString()), self::requestClient());

            if ($result->reason === FailureReason::RATE_LIMITED) {
                throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
            }

            abort_if($result->session === null, 401);

            return ['refresh_token' => $result->session->tokens->refreshToken?->reveal()];
        });

        Route::get(
            '/verify',
            static fn (Request $request): array => ['outcome' => app(VerificationLinks::class)->consume(SignedLink::fromRequest($request), self::requestClient($request))->value],
        )->name('verify');
    }

    /**
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropTypedPrincipalTables();

        Schema::dropIfExists('verifiable_identities');

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A sign-in looks up and limits the identifier in its normalised form.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInLooksUpAndLimitsTheIdentifierInItsNormalForm(): void
    {
        $identity = $this->seedPasswordIdentity('Ada@Example.TEST');

        self::assertSame('ada@example.test', $identity->email);

        $session = $this->signedIn($this->sessions()->signIn('password', ['email' => '  ADA@example.TEST ', 'password' => self::PASSWORD], self::requestContext()));

        self::assertIsModel($identity, $session->identity);
        self::assertTrue($this->freshGuard()->attempt(['email' => 'ada@EXAMPLE.test', 'password' => self::PASSWORD]));

        foreach (['ada@example.test', 'ADA@EXAMPLE.TEST', ' Ada@Example.Test', 'ada@example.TEST ', 'aDa@example.test'] as $email) {
            self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => $email, 'password' => 'wrong'], self::requestContext())->reason);
        }

        $this->recordEvents([AuthenticationFailed::class]);

        $refused = $this->sessions()->signIn('password', ['email' => 'ADA@example.test', 'password' => self::PASSWORD], self::requestContext());

        self::assertSame(FailureReason::RATE_LIMITED, $refused->reason);
        self::assertSame(280, $refused->retryAfter);
        self::assertSame(280, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        self::assertSame('ADA@example.test', $this->recordedEvent(AuthenticationFailed::class)->identifier);

        $rows = DB::table('rate_limits')->orderBy('hits')->get();

        self::assertCount(3, $rows);
        self::assertSame([5, 5, 5], $rows->pluck('hits')->map(static fn (mixed $hits): int => (int) $hits)->all()); // @phpstan-ignore cast.int

        foreach ($rows as $row) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row->key);
        }

        self::assertSame(1, Session::query()->count());
    }

    /**
     * A list of identifiers cannot get around the identifier's limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListOfIdentifiersCannotGetAroundTheIdentifiersLimit(): void
    {
        $this->seedPasswordIdentity('ada@example.test');

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertFalse($this->freshGuard()->attempt(['email' => 'ada@example.test', 'password' => 'wrong']));
        }

        $lookups = 0;

        DB::listen(static function (QueryExecuted $query) use (&$lookups): void {
            $lookups += str_contains($query->sql, 'verifiable_identities') ? 1 : 0;
        });

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertFalse($this->freshGuard()->attempt(['email' => ['ada@example.test'], 'password' => 'wrong']));
        }

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertFalse($this->freshGuard()->attempt(['email' => ['ada@example.test'], 'password' => self::PASSWORD]));
        self::assertSame(0, $lookups);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * Every password checked counts against the account, however it was found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryPasswordCheckedCountsAgainstTheAccountHoweverItWasFound(): void
    {
        $this->seedPasswordIdentity('ada@example.test');

        $byClosure = static fn (Builder $query): Builder => $query->where('email', 'ada@example.test');

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertFalse($this->freshGuard()->attempt(['email' => $byClosure, 'password' => 'wrong']));
        }

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertFalse($this->freshGuard()->attempt(['email' => $byClosure, 'password' => self::PASSWORD]));
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(280, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);

        $this->recordEvents([AuthenticationFailed::class]);

        $refused = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertNull($refused->retryAfter);
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(280, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        EventContextAssertions::assertIdentity(null, $this->recordedEvent(AuthenticationFailed::class)->context);
        self::assertSame('ada@example.test', $this->recordedEvent(AuthenticationFailed::class)->identifier);

        Carbon::setTestNow(Carbon::now()->addSeconds(280));
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(280));

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
    }

    /**
     * An account's limit holds across every guard that checks it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccountsLimitHoldsAcrossEveryGuardThatChecksIt(): void
    {
        $identity = $this->seedPasswordIdentity('ada@example.test');
        $byNumber = ['id' => (string) $identity->getKey(), 'password' => 'wrong']; // @phpstan-ignore cast.string

        for ($attempt = 0; $attempt < 3; $attempt++) {
            self::assertSame(
                FailureReason::INVALID_CREDENTIALS,
                $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext())->reason,
            );
        }

        for ($attempt = 0; $attempt < 2; $attempt++) {
            self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions('by_number')->signIn('password', $byNumber, self::requestContext())->reason);
        }

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', self::credentials(), self::requestContext())->reason);
        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            $this->sessions('by_number')->signIn('password', ['password' => self::PASSWORD] + $byNumber, self::requestContext())->reason,
        );
        self::assertFalse($this->freshGuard('by_number')->attempt(['password' => self::PASSWORD] + $byNumber));
        self::assertSame(0, Session::query()->count());

        Carbon::setTestNow(Carbon::now()->addSeconds(280));
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(280));

        self::assertTrue($this->sessions('by_number')->signIn('password', ['password' => self::PASSWORD] + $byNumber, self::requestContext())->isSignedIn());
    }

    /**
     * The most permissive guard bounds the account.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheMostPermissiveGuardBoundsTheAccount(): void
    {
        $this->seedPasswordIdentity('ada@example.test');

        $wrong = ['email' => 'ada@example.test', 'password' => 'wrong'];

        foreach (['api', 'loose'] as $guard) {
            for ($attempt = 0; $attempt < 5; $attempt++) {
                self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions($guard)->signIn('password', $wrong, self::requestContext())->reason);
            }
        }

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions('loose')->signIn('password', self::credentials(), self::requestContext())->reason);
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(10, self::counterHits('sign_in', 'per_account', AccountAttempts::account(VerifiableIdentity::query()->sole())));
    }

    /**
     * Model classes over one table share the account's limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testModelClassesOverOneTableShareTheAccountsLimit(): void
    {
        $this->seedPasswordIdentity('ada@example.test');

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertSame(
                FailureReason::INVALID_CREDENTIALS,
                $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'], self::requestContext())->reason,
            );
        }

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions('staff')->signIn('password', self::credentials(), self::requestContext())->reason);
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertFalse($this->freshGuard('staff')->attempt(self::credentials()));
        self::assertSame(0, Session::query()->count());
    }

    /**
     * On MySQL, collation variants of an address share the account's limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCollationVariantsOfAnAddressShareTheAccountsLimitOnMySql(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL\'s default collation finds an account by these variants.');
        }

        $this->seedPasswordIdentity('victim@example.test');

        $variants = ["v\u{00ED}ctim@example.test", "vic\u{200B}tim@example.test", "\u{FF56}ictim@example.test", "victi\u{0301}m@example.test", "victim@ex\u{00E1}mple.test"];

        foreach ($variants as $variant) {
            self::assertSame(1, VerifiableIdentity::query()->where('email', $variant)->count(), "MySQL no longer finds the account by {$variant}");
            self::assertSame(
                FailureReason::INVALID_CREDENTIALS,
                $this->sessions()->signIn('password', ['email' => $variant, 'password' => 'wrong'], self::requestContext())->reason,
            );
        }

        $refused = $this->sessions()->signIn('password', ['email' => "victi\u{200B}m@example.test", 'password' => self::PASSWORD], self::requestContext());

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * A further factor can be guessed no more often than the account's
     * password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFurtherFactorIsGuessedNoMoreOftenThanTheAccountsPassword(): void
    {
        $identity = $this->seedPasswordIdentity('ada@example.test');
        $byNumber = ['id' => (string) $identity->getKey(), 'password' => self::PASSWORD]; // @phpstan-ignore cast.string

        self::requireAFurtherFactor();

        foreach ([['api', self::credentials()], ['by_number', $byNumber]] as [$guard, $credentials]) {
            for ($guess = 0; $guess < ($guard === 'api' ? 3 : 2); $guess++) {

                $credential = $this->sessions($guard)->signIn('password', $credentials, self::requestContext())->credential?->reveal();

                self::assertNotNull($credential, "Expected a pending session through {$guard}");
                self::assertTrue($this->sessions($guard)->discard($credential, self::requestClient()));
            }
        }

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', self::credentials(), self::requestContext())->reason);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions('by_number')->signIn('password', $byNumber, self::requestContext())->reason);
        self::assertSame(5, Session::query()->where('status', 'pending')->where('revoked_reason', 'signed_out')->count());
        self::assertSame(0, Session::query()->whereNull('revoked_at')->count());
    }

    /**
     * On MySQL, collation variants cannot mint more pending sessions than the
     * account allows.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCollationVariantsShareThePendingSessionLimitOnMySql(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL\'s default collation finds an account by these variants.');
        }

        $this->seedPasswordIdentity('victim@example.test');

        self::requireAFurtherFactor();

        $variants = ["v\u{00ED}ctim@example.test", "vic\u{200B}tim@example.test", "\u{FF56}ictim@example.test", "victi\u{0301}m@example.test", "victim@ex\u{00E1}mple.test"];

        foreach ($variants as $variant) {
            self::assertTrue(
                $this->sessions()->signIn('password', ['email' => $variant, 'password' => self::PASSWORD], self::requestContext())->isPending(),
                "No pending session for {$variant}",
            );
        }

        $refused = $this->sessions()->signIn('password', ['email' => "victi\u{200B}m@example.test", 'password' => self::PASSWORD], self::requestContext());

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertSame(5, Session::query()->where('status', 'pending')->count());
    }

    /**
     * A guard signs in and counts by its own identifier column, given as a
     * string or an integer.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardSignsInAndCountsByItsOwnIdentifierColumn(): void
    {
        $identity = $this->seedPasswordIdentity('ada@example.test');
        $number   = (string) $identity->getKey(); // @phpstan-ignore cast.string

        self::assertTrue($this->sessions('by_number')->signIn('password', ['id' => $number, 'password' => self::PASSWORD], self::requestContext())->isSignedIn());
        self::assertTrue($this->sessions('by_number')->signIn('password', ['id' => (int) $number, 'password' => self::PASSWORD], self::requestContext())->isSignedIn());
        self::assertTrue($this->freshGuard('by_number')->attempt(['id' => (int) $number, 'password' => self::PASSWORD]));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions('by_number')->signIn('password', self::credentials(), self::requestContext())->reason);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertFalse($this->freshGuard('by_number')->attempt(['id' => $attempt % 2 === 0 ? $number : (int) $number, 'password' => 'wrong']));
        }

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertFalse($this->freshGuard('by_number')->attempt(['id' => $number, 'password' => self::PASSWORD]));
        self::assertSame(FailureReason::RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame($number, $this->recordedEvent(AuthenticationFailed::class)->identifier);
        self::assertEquals(5, self::counterHits('by_number', 'sign_in', 'per_identifier', $number));
    }

    /**
     * An integer identifier never finds an account by MySQL's loose
     * string-to-number comparison.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIntegerIdentifierNeverFindsAnAccountByLooseComparison(): void
    {
        $this->seedPasswordIdentity('ada@example.test');

        self::assertFalse($this->freshGuard()->attempt(['email' => 0, 'password' => self::PASSWORD]));
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => 0, 'password' => self::PASSWORD], self::requestContext())->reason);
    }

    /**
     * A guard that does not allow the method refuses before counting or looking
     * anyone up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardThatDoesNotAllowTheMethodCountsNothing(): void
    {
        $this->seedPasswordIdentity('ada@example.test');

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions('sso_only')->signIn('password', self::credentials(), self::requestContext())->reason);
        self::assertFalse($this->freshGuard('sso_only')->attempt(self::credentials()));
        self::assertSame(0, DB::table('rate_limits')->count());
        self::assertSame(0, Session::query()->count());
    }

    /**
     * A pending session whose method is no longer allowed is refused as
     * `method_not_allowed`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSessionWhoseMethodIsRemovedIsRefused(): void
    {
        $identity = $this->seedPasswordIdentity('ada@example.test');

        self::requireAFurtherFactor();

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        config()->set('auth.guards.api.application.methods', []);

        $proof = self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->satisfy($result->credential->reveal(), $proof, self::requestClient())->reason);
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->satisfy($result->credential->reveal(), $proof, self::requestClient())->reason);
        self::assertSame(1, Session::query()->where('status', 'pending')->whereNull('revoked_at')->count());
        self::assertSame(0, Session::query()->where('status', 'active')->count());
        self::assertSame(1, SessionProof::query()->count());
    }

    /**
     * Sessions follow the guard's lifetimes whatever the principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionsFollowTheGuardsLifetimesWhateverThePrincipal(): void
    {
        $now    = CarbonImmutable::now();
        $tokens = $this->tokens();

        foreach (['client@example.test' => 'client_staff', 'staff@example.test' => 'staff'] as $email => $type) {

            $session = $this->signedIn($this->sessions('members')->signIn('password', $this->seedMember($email, $type), self::requestContext()));
            $access  = $tokens->parse($session->tokens->accessToken->reveal(), TokenType::ACCESS);
            $refresh = $tokens->parse(self::bodyRefreshToken($session->tokens), TokenType::REFRESH);

            self::assertNotNull($access);
            self::assertNotNull($refresh);
            self::assertNotContains($type, $access);
            self::assertArrayNotHasKey('pty', $access);
            self::assertSame($now->addMinutes(self::MEMBERS_ACCESS_MINUTES)->getTimestamp(), $access[Claims::EXPIRES_AT->value]);
            self::assertSame($now->addMinutes(self::MEMBERS_IDLE_MINUTES)->getTimestamp(), $session->record->getIdleExpiresAt()?->getTimestamp());
            self::assertSame($now->addMinutes(self::MEMBERS_ABSOLUTE_MINUTES)->getTimestamp(), $session->record->getAbsoluteExpiresAt()?->getTimestamp());
            self::assertSame($now->addMinutes(self::MEMBERS_IDLE_MINUTES)->getTimestamp(), $refresh[Claims::EXPIRES_AT->value]);

            $this->bearer($session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['principal' => $session->principal->getPrincipalIdentifier()]);
        }
    }

    /**
     * A rebound application access refuses the principal on sign-in and
     * refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReboundAccessRefusesThePrincipalOnSignInAndRefresh(): void
    {
        self::refuseMembersOfType('contractor');

        self::assertSame(
            FailureReason::PRINCIPAL_INELIGIBLE,
            $this->sessions('members')->signIn('password', $this->seedMember('contractor@example.test', 'contractor'), self::requestContext())->reason,
        );
        self::assertSame(0, Session::query()->count());

        $session = $this->signedIn($this->sessions('members')->signIn('password', $this->seedMember('client@example.test', 'client_staff'), self::requestContext()));

        self::refuseMembersOfType('client_staff');

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull(
            self::sessionsOf($this->freshGuard('members'))->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull(self::stored($session)->getRevokedAt());
    }

    /**
     * The verified identifier gate holds password sign-ins until a link
     * verifies the address.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVerifiedIdentifierGateHoldsPasswordSignInsUntilVerified(): void
    {
        $identity = $this->seedPasswordIdentity('ada@example.test');

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->sessions('verified')->signIn('password', self::credentials(), self::requestContext())->reason);
        self::assertFalse($this->freshGuard('verified')->attempt(self::credentials()));
        self::assertFalse($this->freshGuard('verified')->attempt([
            'email'    => static fn (Builder $query): Builder => $query->where('email', 'ada@example.test'),
            'password' => self::PASSWORD,
        ]));
        $reasons = array_map(static fn (object $event): mixed => $event instanceof AuthenticationFailed ? $event->reason : null, $this->recorded);

        self::assertSame(array_fill(0, 3, FailureReason::IDENTIFIER_UNVERIFIED), $reasons);
        self::assertSame(0, Session::query()->count());

        $this->signedIn($this->sessions('verified')->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext()));

        $link = app(VerificationLinks::class)->create('verified', $identity, 'email', 'verify')->reveal();

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'verified']);

        self::assertSame(1, Session::query()->count());
        self::assertTrue($identity->refresh()->hasVerifiedIdentifier('email'));

        $this->signedIn($this->sessions('verified')->signIn('password', self::credentials(), self::requestContext()));
    }

    /**
     * Refreshes refused for their failures are answered `429` through the
     * route.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefreshesRefusedForTheirFailuresAreAnswered429ThroughTheRoute(): void
    {
        $session = $this->signedIn($this->sessions('members')->signIn('password', $this->seedMember('client@example.test', 'staff'), self::requestContext()));
        $before  = self::stored($session)->getRefreshKey();

        foreach (['not-a-token', 'still-not-a-token', 'never-a-token'] as $token) {
            $this->refresh($token)->assertUnauthorized();
        }

        $this->refresh(self::bodyRefreshToken($session->tokens))
            ->assertStatus(429)
            ->assertHeader('Retry-After', '40');

        self::assertSame($before, self::stored($session)->getRefreshKey());

        $later = CarbonImmutable::createStrict(2026, 5, 1, 9, 1, 0);

        Carbon::setTestNow($later);
        CarbonImmutable::setTestNow($later);

        JWT::$timestamp = $later->getTimestamp();

        $this->refresh(self::bodyRefreshToken($session->tokens))->assertOk();
    }

    /**
     * Configure the guards and providers.
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

        $config->set('auth.providers.verifiable', ['driver' => 'model', 'model' => VerifiableIdentity::class]);
        $config->set('auth.providers.typed', ['driver' => 'model', 'model' => TypedIdentity::class]);
        $config->set('auth.providers.verifiable_staff', ['driver' => 'model', 'model' => VerifiableStaffIdentity::class]);

        $config->set('auth.guards.api', [
            'driver'      => 'jwt',
            'provider'    => 'verifiable',
            'application' => ['methods' => ['password', 'sso']],
        ]);
        $config->set('auth.guards.by_number', [
            'driver'      => 'jwt',
            'provider'    => 'verifiable',
            'application' => ['methods' => ['password']],
            'sign_in'     => ['password_identifier' => 'id'],
        ]);
        $config->set('auth.guards.staff', ['driver' => 'jwt', 'provider' => 'verifiable_staff', 'application' => ['methods' => ['password']]]);
        $config->set('auth.guards.loose', [
            'driver'      => 'jwt',
            'provider'    => 'verifiable',
            'application' => ['methods' => ['password']],
            'rate_limits' => ['sign_in' => ['per_identifier' => ['max' => 10, 'decay_seconds' => 300]]],
        ]);
        $config->set('auth.guards.sso_only', ['driver' => 'jwt', 'provider' => 'verifiable', 'application' => ['methods' => ['sso']]]);
        $config->set('auth.guards.verified', [
            'driver'      => 'jwt',
            'provider'    => 'verifiable',
            'application' => ['methods' => ['password', 'sso'], 'require_verified_identifier' => true],
        ]);
        $config->set('auth.guards.members', [
            'driver'      => 'jwt',
            'provider'    => 'typed',
            'application' => ['methods' => ['password']],
            'rate_limits' => ['refresh' => ['per_ip' => ['max' => 3, 'decay_seconds' => 60]]],
            'jwt'         => [
                'access_ttl_minutes'           => self::MEMBERS_ACCESS_MINUTES,
                'refresh_idle_ttl_minutes'     => self::MEMBERS_IDLE_MINUTES,
                'refresh_absolute_ttl_minutes' => self::MEMBERS_ABSOLUTE_MINUTES,
            ],
        ]);

        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Bind an additional-factor policy that asks every sign-in for a further
     * factor.
     *
     * @return void
     */
    private static function requireAFurtherFactor(): void
    {
        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        app()->instance(AdditionalFactorPolicy::class, $factors);
    }

    /**
     * Bind an application access that keeps memberships of the given `type` out
     * of `members`.
     *
     * @param  string  $type
     * @return void
     */
    private static function refuseMembersOfType(string $type): void
    {
        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(
            static fn (string $guard, Principal $principal): bool => $guard === 'members' && $principal instanceof TypedMembership && $principal->type === $type,
        ));
    }

    /**
     * Persist an identity with a designated email and the shared password.
     *
     * @param  string  $email
     * @return \Tests\Integration\Fixtures\VerifiableIdentity
     */
    private function seedPasswordIdentity(string $email): VerifiableIdentity
    {
        return VerifiableIdentity::query()->create(['email' => $email, 'password' => app(Hasher::class)->make(self::PASSWORD)]);
    }

    /**
     * Persist an identity with one membership of the given `type` and return
     * its credentials.
     *
     * @param  string  $email
     * @param  ?string  $type
     * @return array<string, string>
     */
    private function seedMember(string $email, ?string $type): array
    {
        $identity = TypedIdentity::query()->create(['email' => $email, 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $tenant   = TypedTenant::query()->create(['category' => null]);

        TypedMembership::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey(), 'type' => $type]);

        return self::credentials($email);
    }

    /**
     * The session a sign-in started, asserting it started one.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private function signedIn(SignInResult $result): SignedInSession
    {
        self::assertNotNull($result->session, 'Expected the sign-in to start a session; it failed with ' . $result->reason?->value);

        return $result->session;
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
     * The session as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private static function stored(SignedInSession $session): Session
    {
        return Session::query()->whereKey($session->record->getSessionIdentifier())->firstOrFail();
    }

    /**
     * Send a refresh token to the refresh route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function refresh(#[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson('/refresh', ['refresh_token' => $token]);
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
}
