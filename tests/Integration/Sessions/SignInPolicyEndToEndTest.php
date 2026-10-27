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
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\RefreshFailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\RefreshFailed;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\RateLimiting\DatabaseAttemptLimiter;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\InteractsWithTypedPrincipals;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of signing in, and refreshing, through the bindings the
 * package ships, on whichever engine the suite runs against: the guard audience
 * policy, the database attempt limiter, the identifier normalisers and the
 * verified-identifier gate, configured per guard as an application would.
 *
 * - `api`: identities with a designated email, the password and `sso` methods.
 * - `by_number`: the same identities, signing in by their `id` with a password.
 * - `sso_only`: the same identities, the `sso` method only.
 * - `verified`: the same identities, verified identifiers required.
 * - `members`: typed memberships; only `staff` and `client_staff` principals,
 *   with shorter lifetimes for `client_staff`, and at most three failed
 *   refreshes per IP address a minute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(GuardAudiencePolicy::class)]
#[CoversClass(DatabaseAttemptLimiter::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(VerificationLinks::class)]
final class SignInPolicyEndToEndTest extends TestCase
{
    use InteractsWithSessions, InteractsWithTypedPrincipals, InteractsWithVerifiableIdentities;

    /** @var int Access lifetime of a `client_staff` principal, in minutes. */
    private const int CLIENT_STAFF_ACCESS_MINUTES = 2;

    /** @var int Idle lifetime of a `client_staff` session, in minutes. */
    private const int CLIENT_STAFF_IDLE_MINUTES = 60;

    /** @var int Absolute lifetime of a `client_staff` session, in minutes. */
    private const int CLIENT_STAFF_ABSOLUTE_MINUTES = 1440;

    /**
     * Freeze the clocks twenty seconds into a minute, create the tables, and
     * add the routes an application would.
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

        Route::middleware('auth:members')->get('/type', static fn (): array => ['type' => Auth::type()]);

        Route::post('/refresh', static function (Request $request): array {

            $guard = app('auth')->guard('members');

            assert($guard instanceof JwtGuard);

            $pair = $guard->refresh($request->string('refresh_token')->toString());

            abort_if($pair === null, 401);

            return ['refresh_token' => $pair->refreshToken];
        });

        Route::get('/verify', static fn (Request $request): array => ['outcome' => app(VerificationLinks::class)->consume($request)?->value])->name('verify');
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
     * A sign-in finds the identity whatever the casing and spacing of the
     * address, and every form of it counts against one limit: after a success
     * gives its slot back, five failures under different casings use the
     * identifier's limit, and the account's, up, and the next sign-in is
     * refused without its password being checked, with the wait to the end of
     * the window. The limits store digests only.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInLooksUpAndLimitsTheIdentifierInItsNormalForm(): void
    {
        $identity = $this->seedPasswordIdentity('Ada@Example.TEST');

        self::assertSame('ada@example.test', $identity->email);

        $session = $this->signedIn($this->sessions()->signIn('password', ['email' => '  ADA@example.TEST ', 'password' => self::PASSWORD]));

        self::assertTrue($identity->is($session->identity));
        self::assertTrue($this->freshGuard()->attempt(['email' => 'ada@EXAMPLE.test', 'password' => self::PASSWORD]));

        foreach (['ada@example.test', 'ADA@EXAMPLE.TEST', ' Ada@Example.Test', 'ada@example.TEST ', 'aDa@example.test'] as $email) {
            self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => $email, 'password' => 'wrong'])->reason);
        }

        $this->recordEvents([SignInFailed::class]);

        $refused = $this->sessions()->signIn('password', ['email' => 'ADA@example.test', 'password' => self::PASSWORD]);

        self::assertSame(SignInFailureReason::RATE_LIMITED, $refused->reason);
        self::assertSame(280, $refused->retryAfter);
        self::assertSame(280, $this->recordedEvent(SignInFailed::class)->retryAfter);
        self::assertSame('ADA@example.test', $this->recordedEvent(SignInFailed::class)->identifier);

        $rows = DB::table('rate_limits')->orderBy('hits')->get();

        self::assertCount(3, $rows);
        self::assertSame([5, 5, 5], $rows->pluck('hits')->map(static fn (mixed $hits): int => (int) $hits)->all()); // @phpstan-ignore cast.int

        foreach ($rows as $row) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $row->key);
        }

        self::assertSame(1, Device::query()->count());
    }

    /**
     * `attempt()` refuses a list of addresses under the identifier key before
     * any lookup: once the address has used its limit up, the list cannot be
     * used to keep guessing, nor to sign in with the right password.
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

        $this->recordEvents([SignInFailed::class]);

        self::assertFalse($this->freshGuard()->attempt(['email' => ['ada@example.test'], 'password' => self::PASSWORD]));
        self::assertSame(0, $lookups);
        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->recordedEvent(SignInFailed::class)->reason);
    }

    /**
     * Every password checked against an account counts against the account,
     * however the attempt found it: after five wrong passwords through query
     * closures (which name no identifier to count), the right password is
     * refused, as a wrong one is, even through the plain address, until the
     * window ends. The client is told only `invalid_credentials`;
     * `SignInFailed` tells listeners the account's limit refused it, with the
     * wait.
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

        $this->recordEvents([SignInFailed::class]);

        self::assertFalse($this->freshGuard()->attempt(['email' => $byClosure, 'password' => self::PASSWORD]));
        self::assertSame(SignInFailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(SignInFailed::class)->reason);
        self::assertSame(280, $this->recordedEvent(SignInFailed::class)->retryAfter);

        $this->recordEvents([SignInFailed::class]);

        $refused = $this->sessions()->signIn('password', self::credentials());

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertNull($refused->retryAfter);
        self::assertSame(SignInFailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(SignInFailed::class)->reason);
        self::assertSame(280, $this->recordedEvent(SignInFailed::class)->retryAfter);
        self::assertNull($this->recordedEvent(SignInFailed::class)->identity);
        self::assertSame('ada@example.test', $this->recordedEvent(SignInFailed::class)->identifier);

        Carbon::setTestNow(Carbon::now()->addSeconds(280));
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(280));

        self::assertTrue($this->sessions()->signIn('password', self::credentials())->isSignedIn());
    }

    /**
     * An account's password guesses are bounded however many guards check it:
     * `api` (by address) and `by_number` (by id) share the account's provider,
     * and three wrong passwords through one and two through the other use the
     * account's one limit up, so the right password is refused through both,
     * and through `signIn()` and `attempt()` alike, until the window ends.
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
            self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'wrong'])->reason);
        }

        for ($attempt = 0; $attempt < 2; $attempt++) {
            self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions('by_number')->signIn('password', $byNumber)->reason);
        }

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', self::credentials())->reason);
        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions('by_number')->signIn('password', ['password' => self::PASSWORD] + $byNumber)->reason);
        self::assertFalse($this->freshGuard('by_number')->attempt(['password' => self::PASSWORD] + $byNumber));
        self::assertSame(0, Device::query()->count());

        Carbon::setTestNow(Carbon::now()->addSeconds(280));
        CarbonImmutable::setTestNow(CarbonImmutable::now()->addSeconds(280));

        self::assertTrue($this->sessions('by_number')->signIn('password', ['password' => self::PASSWORD] + $byNumber)->isSignedIn());
    }

    /**
     * On MySQL, whose default collation compares accented, full-width and
     * invisible variants of a letter as equal, every variant of an address
     * finds the same account; five wrong passwords spread over five variants
     * use the account's limit up, and a sixth variant with the right password
     * is refused.
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
            self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', ['email' => $variant, 'password' => 'wrong'])->reason);
        }

        $refused = $this->sessions()->signIn('password', ['email' => "victi\u{200B}m@example.test", 'password' => self::PASSWORD]);

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertSame(0, Device::query()->count());
    }

    /**
     * A sign-in waiting for a further factor keeps the slot its password check
     * took on the account, so the factor can be guessed no more often than the
     * password, however the sign-ins name the account: five pending sign-ins
     * through two guards and two identifiers, each discarded as a failed
     * factor, use the account's limit up, and a sixth sign-in with the right
     * password mints no pending sign-in.
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

                $pending = $this->sessions($guard)->signIn('password', $credentials)->pending;

                self::assertNotNull($pending, "Expected a pending sign-in through {$guard}");
                self::assertTrue($this->sessions($guard)->discard($pending->token));
            }
        }

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions()->signIn('password', self::credentials())->reason);
        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions('by_number')->signIn('password', $byNumber)->reason);
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * On MySQL, whose default collation finds one account by many variants of
     * its address, each variant has its own identifier limit but the account
     * one: five pending sign-ins through five variants use it up, and a sixth
     * variant with the right password mints no pending sign-in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCollationVariantsCannotMintMorePendingSignInsThanTheAccountAllowsOnMySql(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL\'s default collation finds an account by these variants.');
        }

        $this->seedPasswordIdentity('victim@example.test');

        self::requireAFurtherFactor();

        $variants = ["v\u{00ED}ctim@example.test", "vic\u{200B}tim@example.test", "\u{FF56}ictim@example.test", "victi\u{0301}m@example.test", "victim@ex\u{00E1}mple.test"];

        foreach ($variants as $variant) {
            self::assertTrue($this->sessions()->signIn('password', ['email' => $variant, 'password' => self::PASSWORD])->requiresFactor(), "No pending sign-in for {$variant}");
        }

        $refused = $this->sessions()->signIn('password', ['email' => "victi\u{200B}m@example.test", 'password' => self::PASSWORD]);

        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $refused->reason);
        self::assertSame(5, PendingSignIn::query()->count());
    }

    /**
     * A guard that names its own identifier column signs in by that column,
     * through `signIn()` and `attempt()` alike, ignores the package's, and
     * counts its attempts against the identifier under that column: after five
     * wrong passwords the right one is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardSignsInAndCountsByItsOwnIdentifierColumn(): void
    {
        $identity = $this->seedPasswordIdentity('ada@example.test');
        $number   = (string) $identity->getKey(); // @phpstan-ignore cast.string

        self::assertTrue($this->sessions('by_number')->signIn('password', ['id' => $number, 'password' => self::PASSWORD])->isSignedIn());
        self::assertSame(SignInFailureReason::INVALID_CREDENTIALS, $this->sessions('by_number')->signIn('password', self::credentials())->reason);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            self::assertFalse($this->freshGuard('by_number')->attempt(['id' => $number, 'password' => 'wrong']));
        }

        $this->recordEvents([SignInFailed::class]);

        self::assertFalse($this->freshGuard('by_number')->attempt(['id' => $number, 'password' => self::PASSWORD]));
        self::assertSame(SignInFailureReason::RATE_LIMITED, $this->recordedEvent(SignInFailed::class)->reason);
        self::assertSame($number, $this->recordedEvent(SignInFailed::class)->identifier);
        self::assertEquals(5, DB::table('rate_limits')->where('key', hash('sha256', "by_number\0sign_in\0per_identifier\0{$number}"))->value('hits'));
    }

    /**
     * A guard that does not allow the method refuses the sign-in before
     * counting it or looking anyone up, and creates nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardThatDoesNotAllowTheMethodCountsNothing(): void
    {
        $this->seedPasswordIdentity('ada@example.test');

        self::assertSame(SignInFailureReason::METHOD_NOT_ALLOWED, $this->sessions('sso_only')->signIn('password', self::credentials())->reason);
        self::assertFalse($this->freshGuard('sso_only')->attempt(self::credentials()));
        self::assertSame(0, DB::table('rate_limits')->count());
        self::assertSame(0, Device::query()->count());
    }

    /**
     * A session of a typed principal carries the type on its access token, not
     * on its refresh token, and lasts as the guard sets for that type: the
     * device's deadlines, the access token's expiry, and the refresh token's,
     * which is the idle deadline. The bearer request reads the type from the
     * bound principal. A `staff` principal, with no lifetimes of its own, gets
     * the guard's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSessionsCarryThePrincipalTypeAndFollowItsLifetimes(): void
    {
        $now     = CarbonImmutable::now();
        $session = $this->signedIn($this->sessions('members')->signIn('password', $this->seedMember('client@example.test', 'client_staff')));
        $tokens  = $this->tokens();
        $access  = $tokens->parse($session->tokens->accessToken, TokenType::ACCESS);
        $refresh = $tokens->parse($session->tokens->refreshToken, TokenType::REFRESH);

        self::assertNotNull($access);
        self::assertNotNull($refresh);
        self::assertSame('client_staff', $access[Claims::PRINCIPAL_TYPE->value]);
        self::assertArrayNotHasKey(Claims::PRINCIPAL_TYPE->value, $refresh);
        self::assertSame($now->addMinutes(self::CLIENT_STAFF_ACCESS_MINUTES)->getTimestamp(), $access[Claims::EXPIRES_AT->value]);
        self::assertSame($now->addMinutes(self::CLIENT_STAFF_IDLE_MINUTES)->getTimestamp(), $session->device->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($now->addMinutes(self::CLIENT_STAFF_ABSOLUTE_MINUTES)->getTimestamp(), $session->device->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($now->addMinutes(self::CLIENT_STAFF_IDLE_MINUTES)->getTimestamp(), $refresh[Claims::EXPIRES_AT->value]);

        $this->bearer($session->tokens->accessToken)->assertOk()->assertExactJson(['type' => 'client_staff']);

        $staff       = $this->signedIn($this->sessions('members')->signIn('password', $this->seedMember('staff@example.test', 'staff')));
        $staffAccess = $tokens->parse($staff->tokens->accessToken, TokenType::ACCESS);
        $lifetimes   = $tokens->lifetimes();

        self::assertNotNull($staffAccess);
        self::assertSame('staff', $staffAccess[Claims::PRINCIPAL_TYPE->value]);
        self::assertSame($now->addMinutes($lifetimes->accessTtlMinutes)->getTimestamp(), $staffAccess[Claims::EXPIRES_AT->value]);
        self::assertSame($now->addMinutes($lifetimes->refreshIdleTtlMinutes)->getTimestamp(), $staff->device->getIdleExpiresAt()?->getTimestamp());
    }

    /**
     * The guard admits only the principal types it lists: another type, or a
     * principal with no type at all, is refused before anything is written.
     * When the guard stops listing a type, a session of that type no longer
     * refreshes, and the device is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardAdmitsOnlyTheListedPrincipalTypesOnSignInAndRefresh(): void
    {
        $contractor = $this->seedMember('contractor@example.test', 'contractor');
        $untyped    = $this->seedMember('untyped@example.test', null);

        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->sessions('members')->signIn('password', $contractor)->reason);
        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->sessions('members')->signIn('password', $untyped)->reason);
        self::assertSame(0, Device::query()->count());

        $session = $this->signedIn($this->sessions('members')->signIn('password', $this->seedMember('client@example.test', 'client_staff')));

        config()->set('auth.guards.members.audience.principal_types', ['staff']);

        $this->recordEvents([RefreshFailed::class]);

        self::assertNull($this->freshGuard('members')->refresh($session->tokens->refreshToken));
        self::assertSame(RefreshFailureReason::PRINCIPAL_INELIGIBLE, $this->recordedEvent(RefreshFailed::class)->reason);
        self::assertNull(self::stored($session)->getRevokedAt());
    }

    /**
     * With verified identifiers required, a password sign-in, through the
     * session service or `attempt()`, is refused until the address is verified,
     * even when `attempt()` finds the identity with a query closure instead of
     * the address. A session started for an identity verified elsewhere is not
     * held up. Following a verification link verifies the address without
     * signing anyone in, and the password sign-in then succeeds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVerifiedIdentifierGateHoldsPasswordSignInsUntilALinkVerifiesTheAddress(): void
    {
        $identity = $this->seedPasswordIdentity('ada@example.test');

        $this->recordEvents([SignInFailed::class]);

        self::assertSame(SignInFailureReason::IDENTIFIER_UNVERIFIED, $this->sessions('verified')->signIn('password', self::credentials())->reason);
        self::assertFalse($this->freshGuard('verified')->attempt(self::credentials()));
        self::assertFalse($this->freshGuard('verified')->attempt([
            'email'    => static fn (Builder $query): Builder => $query->where('email', 'ada@example.test'),
            'password' => self::PASSWORD,
        ]));
        $reasons = array_map(static fn (object $event): mixed => $event instanceof SignInFailed ? $event->reason : null, $this->recorded);

        self::assertSame(array_fill(0, 3, SignInFailureReason::IDENTIFIER_UNVERIFIED), $reasons);
        self::assertSame(0, Device::query()->count());

        $this->signedIn($this->sessions('verified')->start($identity, null, 'sso'));

        $link = app(VerificationLinks::class)->create('verified', $identity, 'email', 'verify');

        $this->getJson($link)->assertOk()->assertExactJson(['outcome' => 'verified']);

        self::assertSame(1, Device::query()->count());
        self::assertTrue($identity->refresh()->hasVerifiedIdentifier('email'));

        $this->signedIn($this->sessions('verified')->signIn('password', self::credentials()));
    }

    /**
     * Failed refreshes from one IP address are counted in the database; once
     * the address has used up its limit, even a valid refresh token is answered
     * `429` with the wait to the end of the minute, and its device is left as
     * it was. When the window ends, the token refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefreshesRefusedForTheirFailuresAreAnswered429ThroughTheRoute(): void
    {
        $session = $this->signedIn($this->sessions('members')->signIn('password', $this->seedMember('client@example.test', 'staff')));
        $before  = self::stored($session)->getRefreshKey();

        foreach (['not-a-token', 'still-not-a-token', 'never-a-token'] as $token) {
            $this->refresh($token)->assertUnauthorized();
        }

        $this->refresh($session->tokens->refreshToken)
            ->assertStatus(429)
            ->assertHeader('Retry-After', '40');

        self::assertSame($before, self::stored($session)->getRefreshKey());

        $later = CarbonImmutable::createStrict(2026, 5, 1, 9, 1, 0);

        Carbon::setTestNow($later);
        CarbonImmutable::setTestNow($later);

        JWT::$timestamp = $later->getTimestamp();

        $this->refresh($session->tokens->refreshToken)->assertOk();
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

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'verifiable', 'audience' => ['methods' => ['password', 'sso']]]);
        $config->set('auth.guards.by_number', ['driver' => 'jwt', 'provider' => 'verifiable', 'sign_in' => ['password_identifier' => 'id']]);
        $config->set('auth.guards.sso_only', ['driver' => 'jwt', 'provider' => 'verifiable', 'audience' => ['methods' => ['sso']]]);
        $config->set('auth.guards.verified', [
            'driver'   => 'jwt',
            'provider' => 'verifiable',
            'audience' => ['methods' => ['password', 'sso'], 'require_verified_identifier' => true],
        ]);
        $config->set('auth.guards.members', [
            'driver'      => 'jwt',
            'provider'    => 'typed',
            'audience'    => ['principal_types' => ['staff', 'client_staff']],
            'rate_limits' => ['refresh' => ['per_ip' => ['max' => 3, 'decay_seconds' => 60]]],
            'jwt'         => [
                'by_principal_type' => [
                    'client_staff' => [
                        'access_ttl_minutes'           => self::CLIENT_STAFF_ACCESS_MINUTES,
                        'refresh_idle_ttl_minutes'     => self::CLIENT_STAFF_IDLE_MINUTES,
                        'refresh_absolute_ttl_minutes' => self::CLIENT_STAFF_ABSOLUTE_MINUTES,
                    ],
                ],
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
        $factors->shouldReceive('requiresAdditionalFactor')->andReturnTrue();

        app()->instance(AdditionalFactorPolicy::class, $factors);
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
     * Persist a typed identity with one membership of the type, in a tenant of
     * no type, and return its password credentials.
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
     * The session's device as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private static function stored(SignedInSession $session): Device
    {
        return Device::query()->whereKey($session->device->getDeviceIdentifier())->firstOrFail();
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

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/type');
    }
}
