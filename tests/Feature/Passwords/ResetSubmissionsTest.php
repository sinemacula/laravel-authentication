<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Database\QueryException;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\RequestBody;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Passwords\SendPasswordReset;
use SineMacula\Laravel\Authentication\Testing\FakeBreachedPasswordChecker;
use Tests\Concerns\InspectsTraces;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\Fixtures\Passwords\FailingBreachedPasswordChecker;
use Tests\Fixtures\Passwords\RecordingTimebox;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\TestCase;

/**
 * Feature tests of password resets through `Auth::passwords()`, by link and by
 * code, over HTTP routes registered as an application would and through the
 * service: the end of every session a reset brings, single use, the binding to
 * a guard, the policy, expiry, replacement, the code's attempts, malformed
 * input, and the submission limit taken before anything else.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetSubmissions::class)]
#[CoversClass(PasswordService::class)]
#[CoversClass(SendPasswordReset::class)]
final class ResetSubmissionsTest extends TestCase
{
    use InspectsTraces, InteractsWithPasswordResets;

    /**
     * A reset link requested over HTTP arrives after the response; its token
     * sets the new password, ends every session of the identity through every
     * guard (`password_reset`), and reports `PasswordSet` for the reset. The
     * old password stops working and the new one signs in; the token works
     * once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkResetsThePasswordAndEndsEverySession(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);
        $this->signInWithPassword('admin', self::EMAIL);
        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class, AuthenticationFailed::class]);

        $this->postJson('/password/forgot', ['email' => ' ADA@example.test '])->assertExactJson(['status' => 'sent']);

        $link = $this->links->sent()[0] ?? null;

        self::assertNotNull($link);
        self::assertSame(['web', 'email', self::EMAIL, '2026-10-29 10:30:00'], [$link->guard, $link->type, $link->identifier, $link->expiresAt->format('Y-m-d H:i:s')]);
        self::assertIsModel(PasswordIdentity::query()->sole(), $link->identity);
        self::assertSame(0, $this->codes->count());

        $token = $link->token()->reveal();

        $this->postJson('/password/reset', ['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])
            ->assertExactJson(['status' => 'reset', 'revoked' => 2, 'violations' => []]);

        self::assertSame(['password_reset', 'password_reset'], DB::table('authentication_sessions')->pluck('revoked_reason')->all());
        self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $this->recordedClasses());
        self::assertSame(PasswordFlow::RESET, $this->recordedEvent(PasswordSet::class)->flow);
        self::assertSame(self::NOW, PasswordIdentity::query()->sole()->tokens_valid_after?->format('Y-m-d H:i:s'));
        self::assertNull($this->sessions('web')->signIn('password', self::credentials(self::EMAIL), self::requestContext())->session);
        self::assertNotNull($this->sessions('web')->signIn('password', ['email' => self::EMAIL, 'password' => self::NEW_PASSWORD], self::requestContext())->session);

        $this->postJson('/password/reset', ['email' => self::EMAIL, 'token' => $token, 'password' => 'yet another passphrase'])
            ->assertExactJson(['status' => 'invalid', 'revoked' => 0, 'violations' => []]);
    }

    /**
     * A reset code goes to the identity's own number through the code sender
     * with the reset purpose, and resets the password as a link does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeResetsThePassword(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $this->postJson('/password/forgot/code', ['phone' => self::PHONE])->assertExactJson(['status' => 'sent']);

        $code = $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);

        self::assertIsString($code);
        self::assertNull($this->codes->lastCodeFor(self::PHONE, CodePurpose::SIGN_IN));

        $this->postJson('/password/reset/code', ['phone' => self::PHONE, 'challenge' => self::challenge(), 'code' => $code, 'password' => self::NEW_PASSWORD])
            ->assertExactJson(['status' => 'reset', 'revoked' => 1, 'violations' => []]);

        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertSame('password_reset', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A reset read from the request reads the body only: a token or a code in
     * the query string is never read, so the reset is `invalid` and the link or
     * code still works from the body, a JSON body or a form one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetFromTheRequestReadsTheBodyOnly(): void
    {
        self::seedResettable();

        Route::post(
            '/password/reset/body',
            static fn (Request $request): array => self::answer(Auth::passwords('web')->reset(RequestBody::fields($request), ClientContext::fromRequest($request))),
        );
        Route::post(
            '/password/reset/code/body',
            static fn (Request $request): array => self::answer(
                Auth::passwords('web')->resetWithCode('phone', RequestBody::fields($request), ClientContext::fromRequest($request)),
            ),
        );

        $token = $this->requestLink();
        $query = http_build_query(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);

        $this->postJson('/password/reset/body?' . $query)->assertExactJson(['status' => 'invalid', 'revoked' => 0, 'violations' => []]);
        $this->postJson('/password/reset/body?token=' . $token, ['email' => self::EMAIL, 'password' => self::NEW_PASSWORD])->assertJsonPath('status', 'invalid');
        $this->postJson('/password/reset/body', ['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->assertJsonPath('status', 'reset');

        $challenge = Auth::passwords('web')->sendResetCode('phone', ['phone' => self::PHONE], self::requestClient())->challengeId;

        app()->terminate();

        $code  = (string) $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);
        $input = ['phone' => self::PHONE, 'challenge' => $challenge, 'code' => $code, 'password' => 'yet another passphrase'];

        $this->postJson('/password/reset/code/body?' . http_build_query($input))->assertJsonPath('status', 'invalid');
        $this->post('/password/reset/code/body', $input)->assertJsonPath('status', 'reset');
    }

    /**
     * A reset's `PasswordSet` and its revocations' events go, once committed,
     * to the dispatcher the guard has at the commit: one swapped in after the
     * reset receives them all, and the dispatcher of the reset none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetsEventsReachTheDispatcherBoundAtTheCommit(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token     = $this->requestLink();
        $guard     = $this->freshGuard('web');
        $passwords = Auth::passwords('web');
        $swapped   = new Dispatcher(app());
        $received  = [];

        $swapped->listen([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class], static function (object $event) use (&$received): void {
            $received[] = $event::class;
        });

        $this->recordEvents([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        DB::transaction(static function () use ($passwords, $guard, $swapped, $token): void {
            self::assertTrue($passwords->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->isReset());

            $guard->setDispatcher($swapped);
        });

        self::assertSame([], $this->recordedClasses());
        self::assertSame([SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $received);
    }

    /**
     * A token or code issued for one guard resets nothing through another.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetIsBoundToItsGuard(): void
    {
        self::seedResettable();

        $this->passwords('admin')->sendResetLink(['email' => self::EMAIL], self::requestClient());
        app()->terminate();

        $token = $this->links->lastTokenFor(self::EMAIL);

        self::assertIsString($token);
        self::assertSame('admin', $this->links->sent()[0]->guard);
        self::assertSame(
            ResetStatus::INVALID,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
        self::assertSame(
            ResetStatus::RESET,
            $this->passwords('admin')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
    }

    /**
     * A password the policy rejects answers its violations and spends nothing:
     * the same token then resets with a password it accepts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARejectedPasswordSpendsNothing(): void
    {
        self::seedResettable();

        $this->recordEvents([AuthenticationFailed::class]);

        $token  = $this->requestLink();
        $result = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'short'], self::requestClient());

        self::assertSame([ResetStatus::PASSWORD_REJECTED, [PasswordViolation::TOO_SHORT]], [$result->status, $result->violations]);
        self::assertFalse($result->isReset());
        self::assertSame([], $this->recordedClasses());
        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
    }

    /**
     * A breached password is `password_rejected` with the violation, over HTTP,
     * and so is any password while the breached-password checker cannot answer
     * and the policy fails closed (the default): the link is spent by neither,
     * nothing is reported, and it resets once the checker is back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBreachedCheckGuardsAReset(): void
    {
        $checker = FakeBreachedPasswordChecker::fake([self::NEW_PASSWORD], $this->app);

        self::seedResettable();

        $before = PasswordIdentity::query()->sole()->password;
        $token  = $this->requestLink();

        $this->recordEvents([AuthenticationFailed::class, PasswordSet::class]);

        $this->postJson('/password/reset', ['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])
            ->assertExactJson(['status' => 'password_rejected', 'revoked' => 0, 'violations' => ['breached']]);

        $checker->unavailable();

        $this->postJson('/password/reset', ['email' => self::EMAIL, 'token' => $token, 'password' => 'another fine passphrase'])
            ->assertExactJson(['status' => 'password_rejected', 'revoked' => 0, 'violations' => ['breach_check_unavailable']]);

        self::assertSame($before, PasswordIdentity::query()->sole()->password);
        self::assertSame(0, DB::table('one_time_codes')->whereNotNull('consumed_at')->count());
        self::assertSame([], $this->recordedClasses());

        $checker->unavailable(false);

        $this->postJson('/password/reset', ['email' => self::EMAIL, 'token' => $token, 'password' => 'another fine passphrase'])
            ->assertExactJson(['status' => 'reset', 'revoked' => 0, 'violations' => []]);
    }

    /**
     * A failure inside the credential timebox, by link or by code, leaves the
     * new password and the token or code out of every frame of its trace, the
     * timebox's closure and what it captured included, even with arguments
     * recorded in traces.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedResetLeavesTheSecretsOutOfTheTrace(): void
    {
        self::seedResettable();

        $token = $this->requestLink();

        self::assertTrue($this->passwords()->sendResetCode('phone', ['phone' => self::PHONE], self::requestClient())->isSent());

        app()->terminate();

        $code = (string) $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);

        app()->instance(BreachedPasswordChecker::class, new FailingBreachedPasswordChecker);

        $byCode = ['phone' => self::PHONE, 'challenge' => self::challenge(CodeBinding::passwordReset('web', 'phone', self::PHONE)), 'code' => $code];

        $resets = [
            [$token, fn (): mixed => $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())],
            [$code, fn (): mixed => $this->passwords()->resetWithCode('phone', [...$byCode, 'password' => self::NEW_PASSWORD], self::requestClient())],
        ];

        foreach ($resets as [$proof, $reset]) {

            $exception = self::withArgumentsInTraces(\RuntimeException::class, $reset);

            self::assertSame('a bug in the checker', $exception->getMessage());
            self::assertContains(Timebox::class, array_column($exception->getTrace(), 'class'));
            self::assertFalse(self::hasInTrace($exception, self::NEW_PASSWORD));
            self::assertFalse(self::hasInTrace($exception, $proof));
        }
    }

    /**
     * Whether the identity may reset is decided again on its row once it is
     * locked: one deactivated after the lookup found it, before the lock, is
     * `invalid`, reported as `identity_inactive`, and its link stays unspent,
     * so it resets once the identity is active again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityDeactivatedAfterTheLookupResetsNothing(): void
    {
        self::seedResettable();

        $token       = $this->requestLink();
        $deactivated = false;

        DB::listen(static function (QueryExecuted $query) use (&$deactivated): void {
            if ($deactivated || !str_starts_with($query->sql, 'select') || !str_contains($query->sql, 'password_identities')) {
                return;
            }

            $deactivated = true;

            DB::table('password_identities')->update(['is_active' => false]);
        });

        $this->recordEvents([AuthenticationFailed::class, PasswordSet::class]);

        self::assertSame(
            ResetStatus::INVALID,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
        self::assertTrue($deactivated);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(0, DB::table('one_time_codes')->whereNotNull('consumed_at')->count());

        DB::table('password_identities')->update(['is_active' => true]);

        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
    }

    /**
     * Under bcrypt, a new password holding a null character, which the hasher
     * would refuse with an exception, is rejected with that violation before
     * the proof is checked: neither the link nor the code is spent or counted,
     * and the code then resets with a password the hasher takes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANullCharacterIsRejectedBeforeTheProofIsSpent(): void
    {
        config()->set('hashing.driver', 'bcrypt');

        self::seedResettable();

        $token = $this->requestLink();

        $challenge = $this->passwords()->sendResetCode('phone', ['phone' => self::PHONE], self::requestClient())->challengeId;

        app()->terminate();

        $code   = (string) $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);
        $link   = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => "correct horse battery\0staple"], self::requestClient());
        $byCode = $this->passwords()->resetWithCode(
            'phone',
            ['phone' => self::PHONE, 'challenge' => $challenge, 'code' => $code, 'password' => "correct horse battery\0staple"],
            self::requestClient(),
        );

        self::assertSame([ResetStatus::PASSWORD_REJECTED, [PasswordViolation::NULL_CHARACTER]], [$link->status, $link->violations]);
        self::assertSame([ResetStatus::PASSWORD_REJECTED, [PasswordViolation::NULL_CHARACTER]], [$byCode->status, $byCode->violations]);
        self::assertSame([0, 0], [(int) DB::table('one_time_codes')->sum('attempts'), DB::table('one_time_codes')->whereNotNull('consumed_at')->count()]);
        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->resetWithCode(
                'phone',
                ['phone' => self::PHONE, 'challenge' => $challenge, 'code' => $code, 'password' => self::NEW_PASSWORD],
                self::requestClient(),
            )->status,
        );
    }

    /**
     * A link expires from the second its lifetime ends, configured or not: it
     * is then `invalid`, reported as `link_expired`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkExpiresWithItsLifetime(): void
    {
        config()->set('authentication.passwords.reset.link_ttl_seconds', 300);

        self::seedResettable();

        $answer = $this->passwords()->sendResetLink(['email' => self::EMAIL], self::requestClient());

        self::assertSame('2026-10-29 09:35:00', $answer->expiresAt?->format('Y-m-d H:i:s'));

        app()->terminate();

        $token = (string) $this->links->lastTokenFor(self::EMAIL);

        self::freezeClock(CarbonImmutable::parse(self::NOW)->addSeconds(300));

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            ResetStatus::INVALID,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(['link_expired', null], [$failed->reason->value, $failed->challengeId]);
    }

    /**
     * A new link, requested once the cooldown has passed, replaces the one
     * before: its token stops working at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testANewLinkReplacesTheOneBefore(): void
    {
        self::seedResettable();

        $first = $this->requestLink();

        self::freezeClock(CarbonImmutable::parse(self::NOW)->addSeconds(60));

        $second = $this->requestLink();

        self::assertNotSame($first, $second);
        self::assertSame(
            ResetStatus::INVALID,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $first, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $second, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
    }

    /**
     * Wrong codes count their attempts: once they are used up the code is
     * locked (`code_exhausted`) and even the right one is refused; nothing is
     * reset, and each refusal names the challenge it answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWrongCodesUseUpTheAttempts(): void
    {
        config()->set('authentication.codes.max_attempts', 2);

        self::seedResettable();

        $this->passwords()->sendResetCode('phone', ['phone' => self::PHONE], self::requestClient());
        app()->terminate();

        $code  = (string) $this->codes->lastCodeFor(self::PHONE);
        $wrong = $code === '000000' ? '111111' : '000000';

        $this->recordEvents([AuthenticationFailed::class]);

        foreach ([$wrong, $wrong, $code] as $attempt) {

            $result = $this->passwords()->resetWithCode(
                'phone',
                ['phone' => self::PHONE, 'challenge' => self::challenge(), 'code' => $attempt, 'password' => self::NEW_PASSWORD],
                self::requestClient(),
            );

            self::assertSame(ResetStatus::INVALID, $result->status);
        }

        $reasons = array_map(static fn (AuthenticationFailed $event): string => $event->reason->value, $this->recorded);

        self::assertSame(['invalid_credentials', 'invalid_credentials', 'code_exhausted'], $reasons);
        self::assertSame(array_fill(0, 3, self::challenge()), array_map(static fn (AuthenticationFailed $event): ?string => $event->challengeId, $this->recorded));
        self::assertSame(0, DB::transactionLevel());
        self::assertEquals(2, DB::table('one_time_codes')->value('attempts'));
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
    }

    /**
     * Rows of a submission that is malformed: each is `invalid`, reported as
     * `invalid_credentials`, before the policy runs.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>}>
     */
    public static function provideMalformedSubmissions(): iterable
    {
        $token = str_repeat('a', 43);

        yield from [
            'no identifier'         => ['link', ['token' => $token, 'password' => self::NEW_PASSWORD]],
            'an empty identifier'   => ['link', ['email' => '', 'token' => $token, 'password' => self::NEW_PASSWORD]],
            'no token'              => ['link', ['email' => self::EMAIL, 'password' => self::NEW_PASSWORD]],
            'a token too short'     => ['link', ['email' => self::EMAIL, 'token' => substr($token, 1), 'password' => self::NEW_PASSWORD]],
            'a code for a link'     => ['link', ['email' => self::EMAIL, 'token' => '123456', 'password' => self::NEW_PASSWORD]],
            'no password'           => ['link', ['email' => self::EMAIL, 'token' => $token]],
            'a password list'       => ['link', ['email' => self::EMAIL, 'token' => $token, 'password' => [self::NEW_PASSWORD]]],
            'a code too long'       => ['code', ['phone' => self::PHONE, 'challenge' => self::NO_CHALLENGE, 'code' => '1234567', 'password' => self::NEW_PASSWORD]],
            'a token for a code'    => ['code', ['phone' => self::PHONE, 'challenge' => self::NO_CHALLENGE, 'code' => $token, 'password' => self::NEW_PASSWORD]],
            'a number not in E.164' => ['code', ['phone' => '07700 900123', 'challenge' => self::NO_CHALLENGE, 'code' => '123456', 'password' => self::NEW_PASSWORD]],
            'no challenge'          => ['code', ['phone' => self::PHONE, 'code' => '123456', 'password' => self::NEW_PASSWORD]],
            'a malformed challenge' => ['code', ['phone' => self::PHONE, 'challenge' => 'NOT-A-CHALLENGE', 'code' => '123456', 'password' => self::NEW_PASSWORD]],
        ];
    }

    /**
     * A malformed submission is refused before the password reaches the policy,
     * still counted against the limits; it names the challenge a code reset
     * answered only when that is in the form the engine issues.
     *
     * @param  string  $channel
     * @param  array<string, mixed>  $input
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedSubmissions')]
    public function testMalformedSubmissionsAreInvalid(string $channel, array $input): void
    {
        $checker = FakeBreachedPasswordChecker::fake(container: $this->app);

        $this->recordEvents([AuthenticationFailed::class]);

        $result = $channel === 'link' ? $this->passwords()->reset($input, self::requestClient()) : $this->passwords()->resetWithCode('phone', $input, self::requestClient());

        self::assertSame([ResetStatus::INVALID, [], null, 0], [$result->status, $result->violations, $result->retryAfter, $result->revoked]);
        $event = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::PASSWORD_RESET, 'invalid_credentials'], [$event->flow, $event->reason->value]);
        self::assertSame(($input['challenge'] ?? null) === self::NO_CHALLENGE ? self::NO_CHALLENGE : null, $event->challengeId);
        self::assertSame(0, $checker->count());
        self::assertGreaterThan(0, DB::table('rate_limits')->count());
    }

    /**
     * Submissions are counted before anything else, so once they are used up a
     * submission never reaches the breached-password check; a reset that
     * succeeds gives its slots back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSubmissionsAreLimitedBeforeAnyCheck(): void
    {
        config()->set('authentication.rate_limits.password_reset.per_identifier', ['max' => 2, 'decay_seconds' => 900]);

        self::seedResettable();

        $checker = FakeBreachedPasswordChecker::fake(container: $this->app);
        $token   = $this->requestLink();
        $wrong   = str_repeat('a', 43);

        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
        self::assertSame(
            ResetStatus::INVALID,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $wrong, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
        self::assertSame(
            ResetStatus::INVALID,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $wrong, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
        self::assertSame(3, $checker->count());

        $this->recordEvents([AuthenticationFailed::class]);

        $limited = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $wrong, 'password' => self::NEW_PASSWORD], self::requestClient());

        self::assertSame([ResetStatus::RATE_LIMITED, 900], [$limited->status, $limited->retryAfter]);
        self::assertSame(['rate_limited', 900], [$this->recordedEvent(AuthenticationFailed::class)->reason->value, $this->recordedEvent(AuthenticationFailed::class)->retryAfter]);
        self::assertSame(3, $checker->count());
    }

    /**
     * A code reset held back by the limits still names the challenge it
     * answered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALimitedCodeResetNamesItsChallenge(): void
    {
        config()->set('authentication.rate_limits.password_reset.per_identifier', ['max' => 1, 'decay_seconds' => 900]);

        $input = ['phone' => self::PHONE, 'challenge' => self::NO_CHALLENGE, 'code' => '123456', 'password' => self::NEW_PASSWORD];

        self::assertSame(ResetStatus::INVALID, $this->passwords()->resetWithCode('phone', $input, self::requestClient())->status);

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(ResetStatus::RATE_LIMITED, $this->passwords()->resetWithCode('phone', $input, self::requestClient())->status);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([FailureReason::RATE_LIMITED, self::NO_CHALLENGE], [$failed->reason, $failed->challengeId]);
    }

    /**
     * A reset that succeeds ends the credential timebox early; one that fails
     * waits it out, a rejected password included, and so does one that fails
     * after a success on the same timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnlyAResetEndsTheTimeboxEarly(): void
    {
        self::seedResettable();

        $token = $this->requestLink();
        $box   = new RecordingTimebox;

        app()->instance(Timebox::class, $box);

        $this->passwords()->reset(['email' => self::EMAIL, 'token' => str_repeat('a', 43), 'password' => self::NEW_PASSWORD], self::requestClient());
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'short'], self::requestClient());
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient());
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient());

        self::assertSame([false, false, true, false], $box->endedEarly);
    }

    /**
     * A client the caller names is the one every event reports, not the request
     * being served: a refusal's, and a reset's `PasswordSet`, the sessions it
     * ends and its `SignedOutEverywhere`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientNamedIsReported(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token  = $this->requestLink();
        $client = new ClientContext('198.51.100.9', 'Kiosk/2.0');

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class]);

        $this->passwords()->reset(['email' => self::EMAIL, 'token' => str_repeat('a', 43), 'password' => self::NEW_PASSWORD], $client);
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], $client);

        self::assertSame([AuthenticationFailed::class, SessionRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $this->recordedClasses());
        self::assertSame([$client, $client, $client, $client], array_map(
            static fn (AuthenticationFailed|PasswordSet|SessionRevoked|SignedOutEverywhere $event): ClientContext => $event->context->client,
            $this->recorded,
        ));
    }

    /**
     * Rows of a setting a reset reads that is malformed, and the message it
     * fails closed with.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        yield from [
            'a code length'      => [['authentication.codes.length' => 4], 'authentication.codes.length must be an integer from 6 to 10.'],
            'a codes key'        => [['authentication.codes.key' => 'short'], 'authentication.codes.key must be a string of at least 32 bytes'],
            'a password minimum' => [['authentication.passwords.min_length' => 3], 'authentication.passwords.min_length must be an integer from 8 to 128.'],
            'a link lifetime'    => [['authentication.passwords.reset.link_ttl_seconds' => 1], 'authentication.passwords.reset.link_ttl_seconds must be an integer'],
        ];
    }

    /**
     * A malformed setting fails a reset closed, naming the key, before the
     * submission is counted.
     *
     * @param  array<string, mixed>  $settings
     * @param  non-empty-string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedSettingsFailBeforeAnythingIsCounted(array $settings, string $message): void
    {
        config()->set($settings);

        try {
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => str_repeat('a', 43), 'password' => self::NEW_PASSWORD], self::requestClient());
            self::fail('A malformed setting was accepted.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith($message, $exception->getMessage());
        }

        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A reset for an identity it found locks that identity's row as the
     * transaction that spends the proof starts, before the token is read, the
     * lock order a password write follows too, so the two wait for each other
     * rather than deadlock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetLocksTheIdentitysRowBeforeTheProof(): void
    {
        $identity   = self::seedResettable();
        $token      = $this->requestLink();
        $statements = self::recordStatements();
        $lock       = $identity->newModelQuery()->whereKey($identity->getKey())->lockForUpdate()->limit(1)->toSql();

        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );

        $at = array_search($lock, $statements(), true);

        self::assertIsInt($at);
        self::assertSame('begin', $statements()[$at - 1]);
        self::assertStringContainsString('one_time_codes', $statements()[$at + 1]);
    }

    /**
     * A reset by code for a type with no normaliser is a misconfiguration,
     * refused before anything is counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACodeResetNeedsANormalizedType(): void
    {
        try {
            $this->passwords()->resetWithCode(
                'username',
                ['username' => 'ada', 'challenge' => self::challenge(), 'code' => '123456', 'password' => self::NEW_PASSWORD],
                self::requestClient(),
            );
            self::fail('A reset code was checked for a type with no normaliser.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Password reset codes need a normaliser registered for identifier type [username]', $exception->getMessage());
        }

        self::assertSame(0, DB::table('rate_limits')->count());
    }

    /**
     * A failure raised inside the reset's transaction, below the closure that
     * spends the proof and writes the password, by link and by code, leaves the
     * new password and the token or code out of every frame of its trace, that
     * closure and what it captured included, even with arguments recorded in
     * traces; nothing is reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureInsideTheResetsTransactionLeavesTheSecretsOutOfTheTrace(): void
    {
        self::seedResettable();

        $token = $this->requestLink();

        self::assertTrue($this->passwords()->sendResetCode('phone', ['phone' => self::PHONE], self::requestClient())->isSent());

        app()->terminate();

        $code   = (string) $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);
        $byCode = ['phone' => self::PHONE, 'challenge' => self::challenge(CodeBinding::passwordReset('web', 'phone', self::PHONE)), 'code' => $code];

        DB::connection()->beforeExecuting(static function (string $query): void {
            if (str_starts_with($query, 'update') && str_contains($query, 'password_identities')) {
                throw new \RuntimeException('The password write failed.');
            }
        });

        $resets = [
            [$token, fn (): mixed => $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())],
            [$code, fn (): mixed => $this->passwords()->resetWithCode('phone', [...$byCode, 'password' => self::NEW_PASSWORD], self::requestClient())],
        ];

        foreach ($resets as [$proof, $reset]) {

            $exception = self::withArgumentsInTraces(\RuntimeException::class, $reset);

            self::assertSame('The password write failed.', $exception->getMessage());
            self::assertTrue(self::passedThroughTheResetsTransaction($exception));
            self::assertFalse(self::dumpsInTrace($exception, self::NEW_PASSWORD));
            self::assertFalse(self::dumpsInTrace($exception, $proof));
        }

        self::assertSame(0, DB::transactionLevel());
        self::assertSame(0, DB::table('one_time_codes')->whereNotNull('consumed_at')->count());
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
    }

    /**
     * A deadlock raised inside a reset's transaction within a caller's is
     * thrown on as Laravel's `DeadlockException`, with the caller's transaction
     * level restored. The caller rolls its whole transaction back: nothing the
     * reset did is kept, nothing is reported, and its retry of the whole
     * transaction resets.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeadlockInsideACallersTransactionIsThrownOnForTheCallerToRetryWhole(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token    = $this->requestLink();
        $deadlock = self::deadlock();
        $level    = DB::transactionLevel();

        self::failOnce('update', 'one_time_codes', $deadlock);

        $this->recordEvents([AuthenticationFailed::class, PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        DB::beginTransaction();

        try {
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient());

            self::fail('The deadlock was not thrown on.');
        } catch (DeadlockException $thrown) {
            self::assertSame($deadlock, $thrown->getPrevious());
        }

        self::assertSame($level + 1, DB::transactionLevel());

        DB::rollBack();

        self::assertSame($level, DB::transactionLevel());
        self::assertSame([], $this->recordedClasses());
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertNull(PasswordIdentity::query()->sole()->tokens_valid_after);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));

        $result = DB::transaction(fn (): mixed => $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient()));

        self::assertInstanceOf(ResetResult::class, $result);
        self::assertSame([ResetStatus::RESET, 1], [$result->status, $result->revoked]);
        self::assertSame('password_reset', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * Outside any transaction, a deadlock raised inside a reset's is rolled
     * back and thrown on as raised, once: nothing the reset did is kept, and
     * the token still resets.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeadlockOutsideAnyTransactionIsRolledBackAndThrownOnAsRaised(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token    = $this->requestLink();
        $deadlock = self::deadlock();
        $raised   = self::failOnce('update', 'one_time_codes', $deadlock);

        try {
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient());

            self::fail('The deadlock was not thrown on.');
        } catch (QueryException $thrown) {
            self::assertSame($deadlock, $thrown);
        }

        self::assertSame(1, $raised());
        self::assertSame(0, DB::transactionLevel());
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
    }

    /**
     * A wrong code inside a caller's transaction completes the reset's nested
     * transaction with its attempt counted: the caller's transaction stays at
     * its level with its own writes, the reset is `invalid`, reported as
     * `invalid_credentials`, and the caller's commit keeps the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedProofInsideACallersTransactionKeepsItsAttempt(): void
    {
        self::seedResettable();

        $this->passwords()->sendResetCode('phone', ['phone' => self::PHONE], self::requestClient());
        app()->terminate();

        $code  = (string) $this->codes->lastCodeFor(self::PHONE);
        $wrong = $code === '000000' ? '111111' : '000000';

        $this->recordEvents([AuthenticationFailed::class]);

        DB::beginTransaction();

        DB::table('password_identities')->update(['nickname' => 'set by the caller']);

        $result = $this->passwords()->resetWithCode(
            'phone',
            ['phone' => self::PHONE, 'challenge' => self::challenge(), 'code' => $wrong, 'password' => self::NEW_PASSWORD],
            self::requestClient(),
        );

        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        self::assertSame(ResetStatus::INVALID, $result->status);
        self::assertSame(FailureReason::INVALID_CREDENTIALS, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertEquals(1, DB::table('one_time_codes')->value('attempts'));
        self::assertSame('set by the caller', PasswordIdentity::query()->sole()->nickname);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
    }

    /**
     * A proof accepted inside a caller's transaction for an identity that may
     * not reset rolls back only what the reset wrote: the link stays unspent,
     * the caller's transaction stays at its level with its own writes and
     * commits them, and the reset is `invalid`, reported as
     * `identity_inactive`. The link resets once the identity is active again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnusableProofInsideACallersTransactionRollsBackOnlyTheResetsWrites(): void
    {
        self::seedResettable();

        $token = $this->requestLink();

        DB::table('password_identities')->update(['is_active' => false]);

        $this->recordEvents([AuthenticationFailed::class]);

        DB::beginTransaction();

        DB::table('password_identities')->update(['nickname' => 'set by the caller']);

        $result = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient());

        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        self::assertSame(ResetStatus::INVALID, $result->status);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame('set by the caller', PasswordIdentity::query()->sole()->nickname);

        DB::table('password_identities')->update(['is_active' => true]);

        self::assertSame(
            ResetStatus::RESET,
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient())->status,
        );
    }

    /**
     * A failure that is no concurrency error, raised inside a reset's
     * transaction within a caller's, is thrown on as raised and rolls back only
     * what the reset wrote: the caller's transaction stays at its level with
     * its own writes, and commits them, the token unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureInsideACallersTransactionRollsBackOnlyTheResetsWrites(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token   = $this->requestLink();
        $failure = new \RuntimeException('The revocation failed.');

        self::failOnce('update', 'authentication_sessions', $failure);

        DB::beginTransaction();

        DB::table('password_identities')->update(['nickname' => 'set by the caller']);

        try {
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], self::requestClient());

            self::fail('The failing revocation was swallowed.');
        } catch (\RuntimeException $thrown) {
            self::assertSame($failure, $thrown);
        }

        self::assertSame(1, DB::transactionLevel());

        DB::commit();

        $identity = PasswordIdentity::query()->sole();

        self::assertSame('set by the caller', $identity->nickname);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->password));
        self::assertNull($identity->tokens_valid_after);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * A deadlock as MySQL reports one, raised by the statement that spends the
     * proof.
     *
     * @return \Illuminate\Database\QueryException
     */
    private static function deadlock(): QueryException
    {
        $cause = new \PDOException('SQLSTATE[40001]: Serialization failure: 1213 Deadlock found when trying to get lock; try restarting transaction');

        return new QueryException('testing', 'update one_time_codes', [], $cause);
    }

    /**
     * Throw the failure from the next statement that starts with the verb and
     * names the table, once, and return how many times it has been thrown.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  \Throwable  $failure
     * @return \Closure(): int
     */
    private static function failOnce(string $verb, string $table, \Throwable $failure): \Closure
    {
        $thrown = 0;

        DB::connection()->beforeExecuting(static function (string $query) use ($verb, $table, $failure, &$thrown): void {
            if ($thrown === 0 && str_starts_with($query, $verb) && str_contains($query, $table)) {
                $thrown++;

                throw $failure;
            }
        });

        return static function () use (&$thrown): int {
            return $thrown;
        };
    }

    /**
     * Whether the trace runs through a transaction whose closure the reset
     * submissions made, so its captures were inspected with the frames.
     *
     * @param  \Throwable  $exception
     * @return bool
     */
    private static function passedThroughTheResetsTransaction(\Throwable $exception): bool
    {
        foreach ($exception->getTrace() as $frame) {

            $work  = $frame['args'][0] ?? null;
            $scope = $work instanceof \Closure ? (new \ReflectionFunction($work))->getClosureScopeClass()?->getName() : null;

            if ($frame['function'] === 'transaction' && $scope === ResetSubmissions::class) {
                return true;
            }
        }

        return false;
    }

    /**
     * Record from now on each statement run, and `begin` where a transaction
     * starts, in order.
     *
     * @return \Closure(): list<string>
     */
    private static function recordStatements(): \Closure
    {
        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        Event::listen(TransactionBeginning::class, static function () use (&$statements): void {
            $statements[] = 'begin';
        });

        return static function () use (&$statements): array {
            return $statements;
        };
    }
}
