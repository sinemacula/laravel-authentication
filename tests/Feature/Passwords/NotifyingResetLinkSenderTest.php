<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Contracts\Auth\CanResetPassword;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\NotifyingResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;
use SineMacula\Laravel\Authentication\Passwords\ResetRequests;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests of the default password reset link sender, Laravel's
 * notification: it delivers a token that resets the password, refuses a guard
 * whose password identifier is not `email`, and fails the job for an identity
 * that cannot be notified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NotifyingResetLinkSender::class)]
#[CoversClass(ResetRequests::class)]
final class NotifyingResetLinkSenderTest extends TestCase
{
    use InteractsWithPasswordResets;

    /**
     * Laravel's notification is the default link sender: a guard whose password
     * identifier is `email` gets Laravel's `ResetPassword`, whose token resets
     * the password.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultSenderSendsLaravelsNotification(): void
    {
        app()->forgetInstance(PasswordResetLinkSender::class);
        app()->singleton(PasswordResetLinkSender::class, NotifyingResetLinkSender::class);

        Notification::fake();

        $identity = self::seedResettable();
        $token    = null;

        $this->passwords()->sendResetLink(['email' => self::EMAIL]);
        app()->terminate();

        Notification::assertSentTo($identity, ResetPassword::class, static function (ResetPassword $notification) use (&$token): bool {
            $token = $notification->token;

            return true;
        });

        self::assertIsString($token);
        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * While Laravel's notification is the sender, a guard identifying passwords
     * by anything but `email` is refused a reset link before anything is
     * counted; with a sender of the application's own it works.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultSenderRefusesAnotherIdentifier(): void
    {
        config()->set('auth.guards.web.sign_in', ['password_identifier' => 'phone']);

        app()->forgetInstance(PasswordResetLinkSender::class);
        app()->singleton(PasswordResetLinkSender::class, NotifyingResetLinkSender::class);

        try {
            $this->passwords()->sendResetLink(['phone' => self::PHONE]);
            self::fail('The default sender was given a phone number to link.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('Guard [web] identifies passwords by [phone], but the bound ' . NotifyingResetLinkSender::class, $exception->getMessage());
        }

        self::assertSame(0, DB::table('rate_limits')->count());

        FakePasswordResetLinkSender::fake($this->app);

        self::assertTrue($this->passwords()->sendResetLink(['phone' => self::PHONE])->isSent());
    }

    /**
     * An identity that cannot be sent Laravel's notification fails the job, so
     * the queue's retry policy applies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultSenderNeedsCanResetPassword(): void
    {
        $link = new PasswordResetLink('web', 'email', self::EMAIL, str_repeat('a', 43), CarbonImmutable::now(), new PlainIdentityFixture(1));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(PlainIdentityFixture::class . ' cannot be sent a password reset link: it does not implement ' . CanResetPassword::class);

        (new NotifyingResetLinkSender)->send($link);
    }
}
