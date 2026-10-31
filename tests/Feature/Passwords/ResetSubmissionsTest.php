<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Events\TransactionBeginning;
use Illuminate\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordViolation;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
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
        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class, PasswordSet::class, AuthenticationFailed::class]);

        $this->postJson('/password/forgot', ['email' => ' ADA@example.test '])->assertExactJson(['status' => 'sent']);

        $link = $this->links->sent()[0] ?? null;

        self::assertNotNull($link);
        self::assertSame(['web', 'email', self::EMAIL, '2026-10-29 10:30:00'], [$link->guard, $link->type, $link->identifier, $link->expiresAt->format('Y-m-d H:i:s')]);
        self::assertTrue(PasswordIdentity::query()->sole()->is($link->identity));
        self::assertSame(0, $this->codes->count());

        $token = $link->token();

        $this->postJson('/password/reset', ['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])
            ->assertExactJson(['status' => 'reset', 'revoked' => 2, 'violations' => []]);

        self::assertSame(['password_reset', 'password_reset'], DB::table('devices')->pluck('revoked_reason')->all());
        self::assertSame([DeviceRevoked::class, DeviceRevoked::class, SignedOutEverywhere::class, PasswordSet::class], $this->recordedClasses());
        self::assertSame(PasswordFlow::RESET, $this->recordedEvent(PasswordSet::class)->flow);
        self::assertSame(self::NOW, PasswordIdentity::query()->sole()->tokens_valid_after?->format('Y-m-d H:i:s'));
        self::assertNull($this->sessions('web')->signIn('password', self::credentials(self::EMAIL))->session);
        self::assertNotNull($this->sessions('web')->signIn('password', ['email' => self::EMAIL, 'password' => self::NEW_PASSWORD])->session);

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

        $this->postJson('/password/reset/code', ['phone' => self::PHONE, 'code' => $code, 'password' => self::NEW_PASSWORD])
            ->assertExactJson(['status' => 'reset', 'revoked' => 1, 'violations' => []]);

        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertSame('password_reset', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * A reset's `PasswordSet` goes, once committed, to the dispatcher the guard
     * had when the password was written, while the revocations' events go to
     * the one it has at the commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetKeepsTheDispatcherOfTheWriteAndTheRevocationsTakeTheOneAtTheCommit(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token     = $this->requestLink();
        $guard     = $this->freshGuard('web');
        $passwords = Auth::passwords('web');
        $swapped   = new Dispatcher(app());
        $received  = [];

        $swapped->listen([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class], static function (object $event) use (&$received): void {
            $received[] = $event::class;
        });

        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        DB::transaction(static function () use ($passwords, $guard, $swapped, $token): void {
            self::assertTrue($passwords->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->isReset());

            $guard->setDispatcher($swapped);
        });

        self::assertSame([PasswordSet::class], $this->recordedClasses());
        self::assertSame([DeviceRevoked::class, SignedOutEverywhere::class], $received);
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

        $this->passwords('admin')->sendResetLink(['email' => self::EMAIL]);
        app()->terminate();

        $token = $this->links->lastTokenFor(self::EMAIL);

        self::assertIsString($token);
        self::assertSame('admin', $this->links->sent()[0]->guard);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        self::assertSame(ResetStatus::RESET, $this->passwords('admin')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
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
        $result = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'short']);

        self::assertSame([ResetStatus::PASSWORD_REJECTED, [PasswordViolation::TOO_SHORT]], [$result->status, $result->violations]);
        self::assertFalse($result->isReset());
        self::assertSame([], $this->recordedClasses());
        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
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

        self::assertTrue($this->passwords()->sendResetCode('phone', ['phone' => self::PHONE])->isSent());

        app()->terminate();

        $code = (string) $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);

        app()->instance(BreachedPasswordChecker::class, new FailingBreachedPasswordChecker);

        $resets = [
            [$token, fn (): mixed => $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])],
            [$code, fn (): mixed => $this->passwords()->resetWithCode('phone', ['phone' => self::PHONE, 'code' => $code, 'password' => self::NEW_PASSWORD])],
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

        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        self::assertTrue($deactivated);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(0, DB::table('one_time_codes')->whereNotNull('consumed_at')->count());

        DB::table('password_identities')->update(['is_active' => true]);

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
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

        self::assertTrue($this->passwords()->sendResetCode('phone', ['phone' => self::PHONE])->isSent());

        app()->terminate();

        $code   = (string) $this->codes->lastCodeFor(self::PHONE, CodePurpose::PASSWORD_RESET);
        $link   = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => "correct horse battery\0staple"]);
        $byCode = $this->passwords()->resetWithCode('phone', ['phone' => self::PHONE, 'code' => $code, 'password' => "correct horse battery\0staple"]);

        self::assertSame([ResetStatus::PASSWORD_REJECTED, [PasswordViolation::NULL_CHARACTER]], [$link->status, $link->violations]);
        self::assertSame([ResetStatus::PASSWORD_REJECTED, [PasswordViolation::NULL_CHARACTER]], [$byCode->status, $byCode->violations]);
        self::assertSame([0, 0], [(int) DB::table('one_time_codes')->sum('attempts'), DB::table('one_time_codes')->whereNotNull('consumed_at')->count()]);
        self::assertSame(ResetStatus::RESET, $this->passwords()->resetWithCode('phone', ['phone' => self::PHONE, 'code' => $code, 'password' => self::NEW_PASSWORD])->status);
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

        $answer = $this->passwords()->sendResetLink(['email' => self::EMAIL]);

        self::assertSame('2026-10-29 09:35:00', $answer->expiresAt?->format('Y-m-d H:i:s'));

        app()->terminate();

        $token = (string) $this->links->lastTokenFor(self::EMAIL);

        self::freezeClock(CarbonImmutable::parse(self::NOW)->addSeconds(300));

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        self::assertSame('link_expired', $this->recordedEvent(AuthenticationFailed::class)->reason->value);
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
        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $first, 'password' => self::NEW_PASSWORD])->status);
        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $second, 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * Wrong codes count their attempts: once they are used up the code is
     * locked (`code_exhausted`) and even the right one is refused; nothing is
     * reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWrongCodesUseUpTheAttempts(): void
    {
        config()->set('authentication.codes.max_attempts', 2);

        self::seedResettable();

        $this->passwords()->sendResetCode('phone', ['phone' => self::PHONE]);
        app()->terminate();

        $code  = (string) $this->codes->lastCodeFor(self::PHONE);
        $wrong = $code === '000000' ? '111111' : '000000';

        $this->recordEvents([AuthenticationFailed::class]);

        foreach ([$wrong, $wrong, $code] as $attempt) {

            $result = $this->passwords()->resetWithCode('phone', ['phone' => self::PHONE, 'code' => $attempt, 'password' => self::NEW_PASSWORD]);

            self::assertSame(ResetStatus::INVALID, $result->status);
        }

        $reasons = array_map(static fn (AuthenticationFailed $event): string => $event->reason->value, $this->recorded);

        self::assertSame(['invalid_credentials', 'invalid_credentials', 'code_exhausted'], $reasons);
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
            'a code too long'       => ['code', ['phone' => self::PHONE, 'code' => '1234567', 'password' => self::NEW_PASSWORD]],
            'a token for a code'    => ['code', ['phone' => self::PHONE, 'code' => $token, 'password' => self::NEW_PASSWORD]],
            'a number not in E.164' => ['code', ['phone' => '07700 900123', 'code' => '123456', 'password' => self::NEW_PASSWORD]],
        ];
    }

    /**
     * A malformed submission is refused before the password reaches the policy,
     * still counted against the limits.
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

        $result = $channel === 'link' ? $this->passwords()->reset($input) : $this->passwords()->resetWithCode('phone', $input);

        self::assertSame([ResetStatus::INVALID, [], null, 0], [$result->status, $result->violations, $result->retryAfter, $result->revoked]);
        $event = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::PASSWORD_RESET, 'invalid_credentials'], [$event->flow, $event->reason->value]);
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

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $wrong, 'password' => self::NEW_PASSWORD])->status);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $wrong, 'password' => self::NEW_PASSWORD])->status);
        self::assertSame(3, $checker->count());

        $this->recordEvents([AuthenticationFailed::class]);

        $limited = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $wrong, 'password' => self::NEW_PASSWORD]);

        self::assertSame([ResetStatus::RATE_LIMITED, 900], [$limited->status, $limited->retryAfter]);
        self::assertSame(['rate_limited', 900], [$this->recordedEvent(AuthenticationFailed::class)->reason->value, $this->recordedEvent(AuthenticationFailed::class)->retryAfter]);
        self::assertSame(3, $checker->count());
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

        $this->passwords()->reset(['email' => self::EMAIL, 'token' => str_repeat('a', 43), 'password' => self::NEW_PASSWORD]);
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'short']);
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);

        self::assertSame([false, false, true, false], $box->endedEarly);
    }

    /**
     * A client the caller names is the one the events report, not the request
     * being served.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheClientNamedIsReported(): void
    {
        self::seedResettable();

        $token  = $this->requestLink();
        $client = new ClientContext('198.51.100.9', 'Kiosk/2.0');

        $this->recordEvents([AuthenticationFailed::class, PasswordSet::class]);

        $this->passwords()->reset(['email' => self::EMAIL, 'token' => str_repeat('a', 43), 'password' => self::NEW_PASSWORD], $client);
        $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD], $client);

        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
        self::assertSame($client, $this->recordedEvent(PasswordSet::class)->context->client);
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
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedSettingsFailBeforeAnythingIsCounted(array $settings, string $message): void
    {
        config()->set($settings);

        try {
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => str_repeat('a', 43), 'password' => self::NEW_PASSWORD]);
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

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);

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
    public function testACodeResetNeedsANormalisedType(): void
    {
        try {
            $this->passwords()->resetWithCode('username', ['username' => 'ada', 'code' => '123456', 'password' => self::NEW_PASSWORD]);
            self::fail('A reset code was checked for a type with no normaliser.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Password reset codes need a normaliser registered for identifier type [username]', $exception->getMessage());
        }

        self::assertSame(0, DB::table('rate_limits')->count());
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
