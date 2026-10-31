<?php

declare(strict_types = 1);

namespace Tests\Feature\Codes;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\TestCase;

/**
 * Feature tests for signing in with a one-time code sent to an email address,
 * through `Auth::sessions($guard)->signIn('email_code', ...)`: the address in
 * its normal form throughout (case, surrounding whitespace, invalid UTF-8), a
 * code only for a verified address, the guard's verified-identifier
 * requirement, verifying an address by code, and the routes over HTTP.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeSignIn::class)]
#[CoversClass(CodeService::class)]
#[CoversClass(SignInMethodManager::class)]
final class EmailCodeSignInTest extends TestCase
{
    use InteractsWithCodeIdentities, InteractsWithRateLimits;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var string The seeded identity's address, as stored. */
    private const string EMAIL = 'ben@example.com';

    /** @var string A look-alike of the address: another domain, which a case- and accent-insensitive collation matches to it. */
    private const string LOOK_ALIKE = 'ben@examplé.com';

    /** @var \SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender The sender the codes are delivered through. */
    private FakeOneTimeCodeSender $sender;

    /**
     * Freeze the clock, create the table, issue known codes and fake the
     * sender.
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

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE, '246802', '975310']);

        $this->sender = FakeOneTimeCodeSender::fake($this->app);
    }

    /**
     * Release the clock and drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The package registers `email_code` for the `email` identifier type.
     *
     * @return void
     */
    public function testThePackageRegistersEmailCodes(): void
    {
        $method = app(SignInMethodManager::class)->method(CodeSignIn::EMAIL);

        self::assertInstanceOf(CodeSignIn::class, $method);
        self::assertSame('email', $method->identifierType('mobile'));
        self::assertSame(' Ben@Example.com', $method->identifier('mobile', ['email' => ' Ben@Example.com', 'phone' => self::PHONE]));
    }

    /**
     * Rows of the address as typed when the code is requested and when it is
     * entered: every spelling of one address in its normal form.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideSpellings(): iterable
    {
        yield from [
            'as stored'                 => [self::EMAIL, self::EMAIL],
            'requested in capitals'     => ['BEN@EXAMPLE.COM', self::EMAIL],
            'requested with whitespace' => ["  Ben@Example.com\t", self::EMAIL],
            'entered in capitals'       => [self::EMAIL, 'Ben@EXAMPLE.com'],
            'entered with whitespace'   => [self::EMAIL, " ben@example.com\n"],
            'mixed both ways'           => ['Ben@X.com ', 'ben@x.com'],
        ];
    }

    /**
     * The code is sent to, bound to, and signs in with the address in its
     * normal form, however either step spells it.
     *
     * @param  string  $requested
     * @param  string  $entered
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSpellings')]
    public function testTheAddressIsNormalisedThroughout(string $requested, string $entered): void
    {
        $identity = self::seedCodeIdentity(email: mb_strtolower(trim($requested)));

        self::assertTrue($this->codeService()->send('email_code', ['email' => $requested])->isSent());

        $this->app?->terminate();

        self::assertSame(self::CODE, $this->sender->lastCodeFor(mb_strtolower(trim($requested)), CodePurpose::SIGN_IN));
        self::assertSame('email', $this->sender->sent()[0]->type);

        $result = $this->signIn(self::CODE, $entered);

        self::assertTrue($result->isSignedIn());
        self::assertTrue($identity->is($result->session?->identity));
        self::assertSame(['email_code', 'email'], [$result->session?->method, Device::query()->sole()->sign_in_identifier_type]);
    }

    /**
     * Rows of addresses the email normaliser refuses.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideInvalidAddresses(): iterable
    {
        yield from [
            'blank'           => ["  \t"],
            'invalid UTF-8'   => ["ben\xC3\x28@example.com"],
            'truncated UTF-8' => ["ben@example.com\xE2\x82"],
        ];
    }

    /**
     * An address the normaliser refuses asks for no code and signs in with
     * none, without counting anything against a code.
     *
     * @param  string  $address
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideInvalidAddresses')]
    public function testAnAddressThatIsNotOneIsRefused(string $address): void
    {
        self::seedCodeIdentity(email: self::EMAIL);

        self::assertSame(CodeRequestStatus::IDENTIFIER_INVALID, $this->codeService()->send('email_code', ['email' => $address])->status);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE, $address)->reason);
        self::assertSame(0, DB::table('one_time_codes')->count());
    }

    /**
     * A code goes only to a verified address; the right code for an unverified
     * one, which only a guess could find, is `identifier_unverified`, and
     * verifies nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAVerifiedAddressGetsACode(): void
    {
        $identity = self::seedCodeIdentity(email: self::EMAIL, verified: false);

        $this->codeService()->send('email_code', ['email' => self::EMAIL]);
        $this->app?->terminate();

        self::assertSame(0, $this->sender->count());
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->signIn(self::CODE)->reason);
        self::assertFalse($identity->fresh()?->hasVerifiedIdentifier('email'));
    }

    /**
     * A code sent to the phone number does not sign in by email, nor the other
     * way round: each is bound to its identifier type.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeIsBoundToItsIdentifierType(): void
    {
        self::seedCodeIdentity(email: self::EMAIL);

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE)->reason);
        self::assertSame(0, self::storedAttempts());

        $this->codeService()->send('email_code', ['email' => self::EMAIL]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->sessions('mobile')->signIn('phone_code', ['phone' => self::PHONE, 'code' => '246802'])->reason);
        self::assertTrue($this->signIn('246802')->isSignedIn());
    }

    /**
     * On a guard that requires verified identifiers, an email code signs in an
     * identity whose address is verified even when its phone number is not: the
     * requirement checks the identifier the sign-in used.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheVerifiedIdentifierRequirementChecksTheAddress(): void
    {
        $identity = self::seedCodeIdentity(email: self::EMAIL, verified: false);

        DB::table('code_identities')->update(['email_verified_at' => '2026-01-01 00:00:00']);

        $this->codeService('console')->send('email_code', ['email' => self::EMAIL]);

        self::assertTrue($this->signIn(self::CODE, guard: 'console')->isSignedIn());
        self::assertFalse($identity->fresh()?->hasVerifiedIdentifier('phone'));
    }

    /**
     * The address is verified by a code sent to it, which does not sign in;
     * once verified, the address receives sign-in codes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAddressIsVerifiedByCodeAndThenSignsIn(): void
    {
        $identity = self::seedCodeIdentity(email: self::EMAIL, verified: false);

        self::assertTrue($this->codeService()->sendVerification($identity, 'email')->isSent());

        $this->app?->terminate();

        $code = $this->sender->lastCodeFor(self::EMAIL, CodePurpose::VERIFY_IDENTIFIER);

        self::assertSame(self::CODE, $code);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn($code)->reason);
        self::assertSame(VerificationOutcome::VERIFIED, $this->codeService()->verify($identity, 'email', $code));

        $this->sender->forget();

        $this->codeService()->send('email_code', ['email' => self::EMAIL]);
        $this->app?->terminate();

        self::assertSame('246802', $this->sender->lastCodeFor(self::EMAIL, CodePurpose::SIGN_IN));
        self::assertTrue($this->signIn('246802')->isSignedIn());
    }

    /**
     * A code requested for a look-alike of a verified address, which a case-
     * and accent-insensitive lookup matches to its holder, is delivered to no
     * one, and even the right code for the look-alike signs in no one, nor
     * counts against the holder's account; the holder's own address is
     * unaffected.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALookAlikeOfAnAddressReachesAndSignsInNoOne(): void
    {
        $holder = self::seedCodeIdentity(email: self::EMAIL);

        $this->configureLookAlikeGuard();

        self::assertTrue($holder->is($this->freshGuard('lookalike')->getProvider()->retrieveByCredentials(['email' => self::LOOK_ALIKE])));
        self::assertTrue($this->codeService('lookalike')->send('email_code', ['email' => self::LOOK_ALIKE])->isSent());

        $this->app?->terminate();

        self::assertSame(0, $this->sender->count());
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE, self::LOOK_ALIKE, 'lookalike')->reason);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(0, Device::query()->count());
        self::assertSame(0, self::counterHits('sign_in', 'per_account', AccountAttempts::account($holder)));

        $this->codeService('lookalike')->send('email_code', ['email' => self::EMAIL]);
        $this->app?->terminate();

        self::assertSame('246802', $this->sender->lastCodeFor(self::EMAIL));
        self::assertTrue($this->signIn('246802', guard: 'lookalike')->isSignedIn());
    }

    /**
     * An identity whose stored address differs from the requested one only in
     * what the address's normal form folds (its case) holds it: it receives the
     * code at its address in normal form and signs in with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAddressStoredInAnotherCaseIsStillItsHolders(): void
    {
        $holder = self::seedCodeIdentity(email: null);

        DB::table('code_identities')->update(['email' => 'Ben@Example.COM', 'email_verified_at' => '2026-01-01 00:00:00']);

        $this->configureLookAlikeGuard();
        $this->codeService('lookalike')->send('email_code', ['email' => self::EMAIL]);
        $this->app?->terminate();

        $message = $this->sender->sent()[0] ?? null;

        self::assertSame(self::EMAIL, $message?->identifier);
        self::assertTrue($holder->is($message->identity));
        self::assertTrue($this->signIn(self::CODE, guard: 'lookalike')->isSignedIn());
    }

    /**
     * On MySQL, whose `utf8mb4_unicode_ci` collation matches an address with an
     * accented look-alike, the package's own `model` provider finds the holder
     * by the look-alike, and still no code reaches it and no session starts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnMySqlTheCollationsLookAlikeReachesAndSignsInNoOne(): void
    {
        if (DB::connection()->getDriverName() !== 'mysql') {
            self::markTestSkipped('Only MySQL\'s collation matches an address with its accented look-alike.');
        }

        $holder = self::seedCodeIdentity(email: self::EMAIL);

        self::assertTrue($holder->is($this->freshGuard('mobile')->getProvider()->retrieveByCredentials(['email' => self::LOOK_ALIKE])));

        $this->codeService()->send('email_code', ['email' => self::LOOK_ALIKE]);
        $this->app?->terminate();

        self::assertSame(0, $this->sender->count());
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE, self::LOOK_ALIKE)->reason);
        self::assertSame(0, Device::query()->count());
    }

    /**
     * An email code request and sign-in over HTTP, with the code read from the
     * sender fake, and a failed sign-in reported with the address as given.
     *
     * @return void
     */
    public function testAnEmailCodeSignsInOverHttp(): void
    {
        self::seedCodeIdentity(email: self::EMAIL);

        Route::post('/codes/email', static function (Request $request): array {
            $result = Auth::codes('mobile')->send('email_code', ['email' => $request->string('email')->toString()]);

            return ['status' => $result->status->value];
        });

        Route::post('/sign-in/email', static function (Request $request): array {
            $result = Auth::sessions('mobile')->signIn('email_code', ['email' => $request->string('email')->toString(), 'code' => $request->string('code')->toString()]);

            abort_unless($result->isSignedIn(), 401);

            return ['access_token' => $result->session?->tokens->accessToken];
        });

        Route::middleware('auth:mobile')->get('/me', static function (): array {
            $identity = Auth::identity();

            return ['email' => $identity instanceof CodeIdentity ? $identity->email : null];
        });

        $this->postJson('/codes/email', ['email' => ' Ben@Example.com'])->assertExactJson(['status' => 'sent']);

        $code = $this->sender->lastCodeFor(self::EMAIL);

        self::assertIsString($code);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->postJson('/sign-in/email', ['email' => 'BEN@example.com', 'code' => '000000'])->assertUnauthorized();

        self::assertSame('BEN@example.com', $this->recordedEvent(AuthenticationFailed::class)->identifier);

        $access = $this->postJson('/sign-in/email', ['email' => 'BEN@example.com', 'code' => $code])->assertOk()->json('access_token');

        self::assertIsString($access);

        Auth::forgetGuards();

        $this->withHeaders(['Authorization' => 'Bearer ' . $access])->getJson('/me')->assertExactJson(['email' => self::EMAIL]);
    }

    /**
     * Configure the guards.
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

        self::configureCodeGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign in to the guard with the code sent to the address.
     *
     * @param  string  $code
     * @param  string  $email
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signIn(string $code, string $email = self::EMAIL, string $guard = 'mobile'): SignInResult
    {
        return $this->sessions($guard)->signIn('email_code', ['email' => $email, 'code' => $code]);
    }
}
