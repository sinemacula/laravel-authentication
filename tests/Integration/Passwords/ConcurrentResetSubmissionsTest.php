<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\TestCase;

/**
 * Integration tests of password resets against the engine the suite runs on,
 * where another request changes the token between a reset's read and its
 * writes, and where the reset fails or its caller rolls back: the token is
 * spent together with the new password, the cutoff and the revocation, or not
 * at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetSubmissions::class)]
final class ConcurrentResetSubmissionsTest extends TestCase
{
    use InteractsWithPasswordResets;

    /**
     * Of two resets with one token, the one that spends it first resets the
     * password; the other, which read the token live, is `invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoResetsWithOneTokenResetOnce(): void
    {
        self::seedResettable();

        $token = $this->requestLink();
        $other = null;

        $this->afterTheTokenIsRead(function () use ($token, &$other): void {
            $other = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'the other passphrase']);
        });

        $first = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);

        self::assertInstanceOf(ResetResult::class, $other);
        self::assertSame([ResetStatus::INVALID, ResetStatus::RESET], [$first->status, $other->status]);
        self::assertTrue(app(Hasher::class)->check('the other passphrase', (string) PasswordIdentity::query()->sole()->password));
    }

    /**
     * A new link issued between a reset's read of the token and its spending it
     * makes the reset `invalid`, and the new link resets.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetRacingANewLinkIsInvalid(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        self::seedResettable();

        $token = $this->requestLink();
        $fresh = null;

        $this->afterTheTokenIsRead(static function () use (&$fresh): void {
            $fresh = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('web', 'email', self::EMAIL), now()->toImmutable(), 3600);
        });

        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        self::assertInstanceOf(IssuedCode::class, $fresh);
        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $fresh->code, 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * A failure after the password is written (the pending sign-ins cannot be
     * ended) rolls the token, the password, the cutoff and the devices back
     * together, reports nothing, and propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterThePasswordRollsEverythingBack(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token = $this->requestLink();

        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        Schema::drop('pending_sign_ins');

        try {
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);
            self::fail('The failing revocation was swallowed.');
        } catch (QueryException $exception) {
            self::assertStringContainsString('pending_sign_ins', $exception->getMessage());
        }

        $identity = PasswordIdentity::query()->sole();

        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->password));
        self::assertNull($identity->tokens_valid_after);
        self::assertNull(DB::table('devices')->value('revoked_at'));
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A reset inside a transaction its caller rolls back resets nothing and
     * reports nothing, and the token can still reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRollbackUndoesTheReset(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token = $this->requestLink();

        $this->recordEvents([PasswordSet::class, DeviceRevoked::class, SignedOutEverywhere::class]);

        DB::beginTransaction();

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertNull(DB::table('devices')->value('revoked_at'));
        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * Run the change once, right after the next reset reads the token and
     * before it spends it, as a concurrent request would.
     *
     * @param  \Closure(): void  $change
     * @return void
     */
    private function afterTheTokenIsRead(\Closure $change): void
    {
        $done = false;

        DB::listen(static function (QueryExecuted $query) use ($change, &$done): void {
            $sql = strtolower($query->sql);

            if ($done || !str_starts_with($sql, 'select') || !str_contains($sql, 'one_time_codes')) {
                return;
            }

            $done = true;

            $change();
        });
    }
}
