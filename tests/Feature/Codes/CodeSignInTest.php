<?php

declare(strict_types = 1);

namespace Tests\Feature\Codes;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\SessionReauthentication;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubVerbatimNormalizer;

/**
 * Feature tests for signing in with a one-time code sent to a phone number,
 * through `Auth::sessions($guard)->signIn('phone_code', ...)`: the session a
 * correct code starts, and how every wrong, expired, exhausted, replayed,
 * foreign or malformed code is refused, counted and reported; and the proof a
 * code records, on a sign-in and on a reauthentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeSignIn::class)]
#[CoversClass(CodeCheck::class)]
#[CoversClass(SessionReauthentication::class)]
final class CodeSignInTest extends TestCase
{
    use InteractsWithCodeIdentities, InteractsWithRateLimits;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock, create the table and issue known codes.
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

        JWT::$timestamp = $this->now->getTimestamp();

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE, '246802', '975310']);
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
     * The code sent to a verified number starts a session for its identity that
     * records the method and the identifier type, and uses the code up; its
     * first proof is the text message to the number in its normal form, with
     * the `sms` value and nothing observed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCodeSentToAVerifiedNumberSignsIn(): void
    {
        $identity = self::seedCodeIdentity();

        self::assertTrue($this->codeService()->send('phone_code', ['phone' => self::PHONE])->isSent());

        $result = $this->signIn(self::CODE);

        self::assertTrue($result->isSignedIn());
        self::assertTrue($identity->is($result->session?->identity));
        self::assertSame(['phone_code', 'phone'], [$result->session?->method, Session::query()->sole()->sign_in_identifier_type]);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));

        $proof = SessionProof::query()->sole();

        self::assertSame(
            ['first_factor', 'phone_code', 'sms', self::PHONE, ['sms']],
            [$proof->kind, $proof->method, $proof->channel_kind, $proof->channel_reference, $proof->methods],
        );
        self::assertNull($proof->user_presence);
    }

    /**
     * The number is accepted with surrounding whitespace, and looked up in its
     * normal form; a number in another format is not a number at all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheNumberIsNormalizedAndOnlyE164IsAccepted(): void
    {
        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE, '+44 7700 900123')->reason);
        self::assertSame(0, self::storedAttempts());
        self::assertTrue($this->signIn(self::CODE, "  +447700900123\t")->isSignedIn());
    }

    /**
     * A code works once: a replay of the code that signed in is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeSignsInOnce(): void
    {
        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertTrue($this->signIn(self::CODE)->isSignedIn());

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE)->reason);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A wrong code is refused and counted against the code; the identity is not
     * named on the failure, which looks as it would for no identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWrongCodeIsRefusedAndCounted(): void
    {
        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);
        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class]);

        $result = $this->signIn('000000');
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $result->reason);
        self::assertSame(1, self::storedAttempts());
        self::assertSame([AuthenticationFlow::SIGN_IN, FailureReason::INVALID_CREDENTIALS, self::PHONE], [$failed->flow, $failed->reason, $failed->identifier]);
        self::assertSame('phone_code', $failed->context->method);
        self::assertNull($failed->context->identity);
        self::assertSame(['phone' => self::PHONE], $this->recordedEvent(Attempting::class)->credentials);
        self::assertSame(['phone' => self::PHONE], $this->recordedEvent(Failed::class)->credentials);
    }

    /**
     * Rows of `[setting the clock or the code apart, reason only the event
     * says]`: an expired code and one that used up its attempts are refused as
     * `invalid_credentials` in the result.
     *
     * @return iterable<string, array{0: string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideConcealedRefusals(): iterable
    {
        yield from [
            'expired'   => ['expired', FailureReason::CODE_EXPIRED],
            'exhausted' => ['exhausted', FailureReason::CODE_EXHAUSTED],
        ];
    }

    /**
     * An expired or exhausted code is refused even when right; the result says
     * `invalid_credentials` and only the event says why.
     *
     * @param  string  $state
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideConcealedRefusals')]
    public function testExpiredAndExhaustedCodesAreConcealed(string $state, FailureReason $reason): void
    {
        config()->set('authentication.codes.max_attempts', 1);

        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        if ($state === 'expired') {
            CarbonImmutable::setTestNow($this->now->addSeconds(600));
        } else {
            $this->signIn('000000');
        }

        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->signIn(self::CODE);

        self::assertSame([FailureReason::INVALID_CREDENTIALS, null], [$result->reason, $result->retryAfter]);
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * After `max_attempts` wrong codes the code is locked until another is
     * requested, which works.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALockedCodeNeedsANewOne(): void
    {
        config()->set('authentication.codes.max_attempts', 2);

        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);
        $this->signIn('000000');
        $this->signIn('000001');

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE)->reason);

        CarbonImmutable::setTestNow($this->now->addSeconds(60));

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertTrue($this->signIn('246802')->isSignedIn());
    }

    /**
     * A code requested for a number no identity has is still issued, so a guess
     * at it is counted and locks it exactly as for a known number; even the
     * right code signs no one in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnknownNumbersCodeIsCountedLikeAnyOther(): void
    {
        config()->set('authentication.codes.max_attempts', 2);

        $this->codeService()->send('phone_code', ['phone' => self::UNKNOWN_PHONE]);
        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn('000000', self::UNKNOWN_PHONE)->reason);
        self::assertSame(1, self::storedAttempts());
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE, self::UNKNOWN_PHONE)->reason);
        self::assertNotNull(DB::table('one_time_codes')->value('consumed_at'));
        $reasons = array_map(static fn (object $event): ?FailureReason => $event instanceof AuthenticationFailed ? $event->reason : null, $this->recorded);

        self::assertSame([FailureReason::INVALID_CREDENTIALS, FailureReason::INVALID_CREDENTIALS], $reasons);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * The right code for an identity whose number is not verified proves the
     * number is held, so the sign-in says `identifier_unverified` rather than
     * hiding it; no session starts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnverifiedNumberIsRefusedOnceTheCodeProvesIt(): void
    {
        self::seedCodeIdentity(verified: false);

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn('000000')->reason);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->signIn(self::CODE)->reason);
        self::assertSame(0, Session::query()->count());
    }

    /**
     * An identity that cannot report its identifiers verified is refused as
     * unverified, however right the code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatCannotReportVerificationIsUnverified(): void
    {
        self::seedCodeIdentity();

        $this->codeService('unverifiable')->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->signIn(self::CODE, guard: 'unverifiable')->reason);
    }

    /**
     * Whatever a provider returns for the number that is not an identity is
     * treated as no one: the right code signs nothing in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWhatIsNotAnIdentityIsNoOne(): void
    {
        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        $provider = \Mockery::mock(IdentityProvider::class);
        $provider->shouldReceive('retrieveByCredentials')->once()->andReturn(\Mockery::mock(Authenticatable::class));

        $request = new SignInRequest('mobile', $provider, ['phone' => self::PHONE, 'challenge' => self::challenge(), 'code' => self::CODE], new ClientContext(null, null));

        self::assertSame(FailureReason::INVALID_CREDENTIALS, app(SignInMethodManager::class)->method('phone_code')->authenticate($request));
    }

    /**
     * An inactive identity's right code is refused by the session service after
     * the method verified it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnInactiveIdentityIsRefused(): void
    {
        self::seedCodeIdentity(active: false);

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);
        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->signIn(self::CODE)->reason);
        self::assertInstanceOf(CodeIdentity::class, $this->recordedEvent(AuthenticationFailed::class)->context->identity);
    }

    /**
     * A code is bound to the guard it was requested for: on another guard that
     * allows the method, the same number and code sign no one in, and count
     * nothing against the code.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeWorksOnlyOnItsGuard(): void
    {
        self::seedCodeIdentity();

        $this->codeService('kiosk')->send('phone_code', ['phone' => self::PHONE]);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE)->reason);
        self::assertSame(0, self::storedAttempts());
        self::assertTrue($this->signIn(self::CODE, guard: 'kiosk')->isSignedIn());
    }

    /**
     * A code sent to verify the number does not sign in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVerificationCodeDoesNotSignIn(): void
    {
        $identity = self::seedCodeIdentity();

        $this->codeService()->sendVerification($identity, 'phone');

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->signIn(self::CODE)->reason);
        self::assertSame(0, self::storedAttempts());
    }

    /**
     * When the account has used up its attempts, the code is not checked at
     * all: the result says `invalid_credentials`, the event says
     * `account_rate_limited`, and the code keeps its attempts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccountWithoutAttemptsLeftLeavesTheCodeAlone(): void
    {
        $identity = self::seedCodeIdentity();

        config()->set('authentication.rate_limits.sign_in.per_identifier', ['max' => 1, 'decay_seconds' => 300]);

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        DB::table('rate_limits')->insert([
            'key'            => self::counterKey('sign_in', 'per_account', AccountAttempts::account($identity)),
            'hits'           => 1,
            'window_ends_at' => '2026-04-06 12:05:00',
        ]);

        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->signIn(self::CODE);

        self::assertSame([FailureReason::INVALID_CREDENTIALS, null], [$result->reason, $result->retryAfter]);
        self::assertSame(FailureReason::ACCOUNT_RATE_LIMITED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(0, self::storedAttempts());
    }

    /**
     * A sign-in by code counts against the account like a password does, and a
     * successful one gives the account's slot back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAccountsLimitCountsCodeChecks(): void
    {
        $identity = self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);
        $this->signIn('000000');

        self::assertSame(1, self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)));
        self::assertSame(1, self::counterHits('mobile', 'sign_in', 'per_identifier', self::PHONE));

        $this->signIn(self::CODE);

        self::assertSame(1, self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)));
    }

    /**
     * Rows of input that cannot carry a code, a number or a challenge id; the
     * live challenge's id is added to every row that sets none, and a row that
     * sets it to `null` has none.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideMalformedInput(): iterable
    {
        yield from [
            'no code'                 => [['phone' => self::PHONE]],
            'a code too short'        => [['phone' => self::PHONE, 'code' => '13579']],
            'a code too long'         => [['phone' => self::PHONE, 'code' => '1357900']],
            'a code as a number'      => [['phone' => self::PHONE, 'code' => 135790]],
            'a code in a list'        => [['phone' => self::PHONE, 'code' => [self::CODE]]],
            'a code with a letter'    => [['phone' => self::PHONE, 'code' => '13579O']],
            'no number'               => [['code' => self::CODE]],
            'a number as an integer'  => [['phone' => 447700900123, 'code' => self::CODE]],
            'a number in a list'      => [['phone' => [self::PHONE], 'code' => self::CODE]],
            'a number without plus'   => [['phone' => '447700900123', 'code' => self::CODE]],
            'no challenge'            => [['phone' => self::PHONE, 'code' => self::CODE, 'challenge' => null]],
            'a challenge in capitals' => [['phone' => self::PHONE, 'code' => self::CODE, 'challenge' => '0195F4A2-7B1C-4000-8000-00000000000A']],
            'a challenge as a number' => [['phone' => self::PHONE, 'code' => self::CODE, 'challenge' => 42]],
            'a challenge in a list'   => [['phone' => self::PHONE, 'code' => self::CODE, 'challenge' => [self::NO_CHALLENGE]]],
        ];
    }

    /**
     * Input without a well-formed number, code and challenge id is refused
     * before any lookup or check: nothing is counted against the code.
     *
     * @param  array<string, mixed>  $input
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedInput')]
    public function testMalformedInputIsRefusedWithoutCountingAgainstTheCode(array $input): void
    {
        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);

        $input  = array_filter([...['challenge' => self::challenge()], ...$input], static fn (mixed $value): bool => $value !== null);
        $result = $this->sessions('mobile')->signIn('phone_code', $input);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, $result->reason);
        self::assertSame(0, self::storedAttempts());
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * The right code for another challenge than the live one (one sent before,
     * or none at all) is refused, and spends no attempt on the live challenge,
     * whose code still signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeNamingAnotherChallengeSpendsNothing(): void
    {
        self::seedCodeIdentity();

        $sessions = $this->sessions('mobile');
        $first    = $this->codeService()->send('phone_code', ['phone' => self::PHONE])->challengeId;

        self::assertIsString($first);

        DB::table('one_time_codes')->update(['issued_at' => '2026-04-06 11:59:00', 'expires_at' => '2026-04-06 12:00:00']);

        $live = $this->codeService()->send('phone_code', ['phone' => self::PHONE])->challengeId;

        self::assertNotSame($first, $live);

        foreach ([$first, self::NO_CHALLENGE] as $other) {
            self::assertSame(FailureReason::INVALID_CREDENTIALS, $sessions->signIn('phone_code', ['phone' => self::PHONE, 'challenge' => $other, 'code' => '246802'])->reason);
        }

        self::assertSame(0, self::storedAttempts());
        self::assertTrue($sessions->signIn('phone_code', ['phone' => self::PHONE, 'challenge' => $live, 'code' => '246802'])->isSignedIn());
    }

    /**
     * A guard whose application does not allow the method refuses it before
     * anything is counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardThatDoesNotAllowTheMethodRefusesIt(): void
    {
        self::seedCodeIdentity();

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->signIn(self::CODE, guard: 'web')->reason);
        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * The identifier is the input under the type's name, as given, when it is a
     * string or a `Stringable`; the type is the method's whatever the guard.
     *
     * @return void
     */
    public function testTheIdentifierIsTheInputUnderTheTypesName(): void
    {
        $method = app(SignInMethodManager::class)->method('phone_code');
        $phone  = new class implements \Stringable {
            /**
             * The number.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return ' +447700900123';
            }
        };

        self::assertSame(['phone', 'phone'], [$method->identifierType('mobile'), $method->identifierType('web')]);
        self::assertSame(' +447700900123', $method->identifier('mobile', ['phone' => ' +447700900123']));
        self::assertSame(' +447700900123', $method->identifier('mobile', ['phone' => $phone]));
        self::assertNull($method->identifier('mobile', ['phone' => 447700900123]));
        self::assertNull($method->identifier('mobile', ['email' => 'ada@example.test']));
    }

    /**
     * The package registers `phone_code` itself, once per process, and an
     * application registers a code method for another identifier type through
     * the container.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationRegistersACodeMethodForAnotherType(): void
    {
        $manager = app(SignInMethodManager::class);

        self::assertSame($manager->method('phone_code'), $manager->method('phone_code'));

        Schema::table('code_identities', static function (Blueprint $blueprint): void {
            $blueprint->string('whatsapp')->nullable();
        });

        config()->set('authentication.identifiers.normalizers.whatsapp', config('authentication.identifiers.normalizers.phone'));
        config()->set('auth.guards.mobile.application.methods', ['whatsapp_code']);

        $manager->extend('whatsapp_code', fn (Application $app): CodeSignIn => $app->make(CodeSignIn::class, ['type' => 'whatsapp']));

        $this->codeService()->send('whatsapp_code', ['whatsapp' => self::PHONE]);

        self::assertSame('whatsapp', $manager->method('whatsapp_code')->identifierType('mobile'));
        self::assertSame(
            FailureReason::INVALID_CREDENTIALS,
            $this->sessions('mobile')->signIn('whatsapp_code', ['whatsapp' => self::PHONE, 'challenge' => self::challenge(), 'code' => '000000'])->reason,
        );
        self::assertSame(1, self::storedAttempts());
    }

    /**
     * A code sent through another identifier type is a proof over an unknown
     * channel, to the identifier in its normal form, with the `otp` value.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeOfAnotherTypeIsAnUnknownChannel(): void
    {
        Schema::table('code_identities', static function (Blueprint $blueprint): void {
            $blueprint->string('whatsapp')->nullable();
            $blueprint->dateTime('whatsapp_verified_at')->nullable();
        });

        config()->set('authentication.identifiers.normalizers.whatsapp', config('authentication.identifiers.normalizers.phone'));
        config()->set('auth.guards.mobile.application.methods', ['whatsapp_code']);

        app(SignInMethodManager::class)->extend('whatsapp_code', fn (Application $app): CodeSignIn => $app->make(CodeSignIn::class, ['type' => 'whatsapp']));

        self::seedCodeIdentity()->forceFill(['whatsapp' => self::PHONE, 'whatsapp_verified_at' => '2026-01-01 00:00:00'])->save();

        self::assertTrue($this->codeService()->send('whatsapp_code', ['whatsapp' => ' ' . self::PHONE])->isSent());
        self::assertTrue($this->sessions('mobile')->signIn('whatsapp_code', ['whatsapp' => self::PHONE, 'challenge' => self::challenge(), 'code' => self::CODE])->isSignedIn());

        $proof = SessionProof::query()->sole();

        self::assertSame(['whatsapp_code', 'unknown', self::PHONE, ['otp']], [$proof->method, $proof->channel_kind, $proof->channel_reference, $proof->methods]);
    }

    /**
     * Rows of `[destination, whether it is recorded]`: destinations that fit
     * the channel reference's 255 characters (counted as characters, not
     * bytes), and one that does not.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideDestinationLengths(): iterable
    {
        yield from [
            'one that fits'               => [str_repeat('h', 255), true],
            'one that fits in characters' => [str_repeat('é', 255), true],
            'one a character over'        => [str_repeat('h', 256), false],
        ];
    }

    /**
     * A code sent to a destination that fits the channel reference is recorded
     * with it; a longer one, which a custom type's normaliser may keep, is
     * recorded with no reference rather than cut.
     *
     * @param  string  $handle
     * @param  bool  $recorded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideDestinationLengths')]
    public function testADestinationIsRecordedOnlyWhenItFits(string $handle, bool $recorded): void
    {
        Schema::table('code_identities', static function (Blueprint $blueprint): void {
            $blueprint->text('handle')->nullable();
            $blueprint->dateTime('handle_verified_at')->nullable();
        });

        config()->set('authentication.identifiers.normalizers.handle', StubVerbatimNormalizer::class);
        config()->set('auth.guards.mobile.application.methods', ['handle_code']);

        app(SignInMethodManager::class)->extend('handle_code', fn (Application $app): CodeSignIn => $app->make(CodeSignIn::class, ['type' => 'handle']));

        self::seedCodeIdentity()->forceFill(['handle' => $handle, 'handle_verified_at' => '2026-01-01 00:00:00'])->save();

        self::assertTrue($this->codeService()->send('handle_code', ['handle' => $handle])->isSent());
        self::assertTrue($this->sessions('mobile')->signIn('handle_code', ['handle' => $handle, 'challenge' => self::challenge(), 'code' => self::CODE])->isSignedIn());
        self::assertSame($recorded ? $handle : null, SessionProof::query()->sole()->channel_reference);
    }

    /**
     * A session reauthenticated with a code records a first-factor
     * reauthentication over the code's channel, to the number in its normal
     * form, with the `sms` value; the new token's `auth_time` moves and its
     * `amr` stays the session's own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeReauthenticatesASessionOverItsChannel(): void
    {
        self::seedCodeIdentity();

        self::assertTrue($this->codeService()->send('phone_code', ['phone' => self::PHONE])->isSent());

        $session = $this->signIn(self::CODE)->session;

        self::assertNotNull($session);

        $later = $this->now->addHour();

        Carbon::setTestNow($later);
        CarbonImmutable::setTestNow($later);

        JWT::$timestamp = $later->getTimestamp();

        self::assertTrue($this->codeService()->send('phone_code', ['phone' => self::PHONE])->isSent());

        $result = $this->sessions('mobile')->reauthenticate($session->record, 'phone_code', ['phone' => ' ' . self::PHONE, 'challenge' => self::challenge(), 'code' => '246802']);

        self::assertTrue($result->isIssued());

        $proof = SessionProof::query()->where('kind', 'first_factor_reauthentication')->sole();

        self::assertSame(
            ['reauthenticate', 'phone_code', 'sms', self::PHONE, ['sms']],
            [$proof->purpose, $proof->method, $proof->channel_kind, $proof->channel_reference, $proof->methods],
        );

        $claims = Auth::manager()->jwt('mobile')->parse((string) $result->accessToken?->reveal(), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame([$later->getTimestamp(), ['sms']], [$claims['auth_time'] ?? null, $claims['amr'] ?? null]);
    }

    /**
     * Rows of identifier types a code method cannot use.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideUnusableTypes(): iterable
    {
        yield from [
            'the code key'      => ['code', 'A code sign-in method cannot use the identifier type [code]: its input key holds the code or its challenge.'],
            'the challenge key' => ['challenge', 'A code sign-in method cannot use the identifier type [challenge]: its input key holds the code or its challenge.'],
            'upper case'        => ['Phone', 'Identifier type [Phone] must be a lower-case letter followed by lower-case letters, digits and underscores.'],
            'empty'             => ['', 'Identifier type [] must be a lower-case letter followed by lower-case letters, digits and underscores.'],
        ];
    }

    /**
     * A code method for a type that is not a valid identifier type, or whose
     * input key would hold the code or its challenge, is a misconfiguration.
     *
     * @param  string  $type
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnusableTypes')]
    public function testACodeMethodRefusesAnUnusableType(string $type, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        app()->make(CodeSignIn::class, ['type' => $type]);
    }

    /**
     * A successful sign-in by code reports `SignedIn` with the method.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASuccessfulSignInReportsTheMethod(): void
    {
        self::seedCodeIdentity();

        $this->codeService()->send('phone_code', ['phone' => self::PHONE]);
        $this->recordEvents([SignedIn::class]);
        $this->signIn(self::CODE);

        self::assertSame('phone_code', $this->recordedEvent(SignedIn::class)->context->method);
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
     * Sign in to the guard with the code sent to the number.
     *
     * @param  string  $code
     * @param  string  $phone
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signIn(string $code, string $phone = self::PHONE, string $guard = 'mobile'): SignInResult
    {
        return $this->sessions($guard)->signIn('phone_code', ['phone' => $phone, 'challenge' => self::challenge(), 'code' => $code]);
    }
}
