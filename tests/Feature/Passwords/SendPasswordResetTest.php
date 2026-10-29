<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Passwords\SendPasswordReset;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\TestCase;

/**
 * Feature tests of the password reset delivery job: it delivers only reset
 * purposes, for a jwt guard, and only the live issuance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SendPasswordReset::class)]
final class SendPasswordResetTest extends TestCase
{
    use InteractsWithPasswordResets;

    /**
     * The delivery job delivers only reset purposes, for a jwt guard, and only
     * while its token or code is live.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeliveryJobRefusesWhatItCannotDeliver(): void
    {
        self::seedResettable();

        $codes  = app(OneTimeCodes::class);
        $issued = $codes->issue(CodeBinding::signIn('web', 'email', self::EMAIL), CarbonImmutable::now());

        self::assertInstanceOf(IssuedCode::class, $issued);

        try {
            (new SendPasswordReset(CodeBinding::signIn('web', 'email', self::EMAIL), $issued))->handle(app());
            self::fail('A sign-in code was delivered as a reset.');
        } catch (\LogicException $exception) {
            self::assertSame(SendPasswordReset::class . ' delivers only password reset links and codes, not [sign_in] codes.', $exception->getMessage());
        }

        config()->set('auth.guards.session', ['driver' => 'session', 'provider' => 'password_identities']);

        try {
            (new SendPasswordReset(CodeBinding::passwordReset('session', 'email', self::EMAIL), $issued))->handle(app());
            self::fail('A reset was delivered for a session guard.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('Auth guard [session] is not a jwt guard, so it sends no password resets.', $exception->getMessage());
        }

        $binding = CodeBinding::passwordResetLink('web', 'email', self::EMAIL);
        $first   = $codes->issueToken($binding, CarbonImmutable::now(), 3600);
        $second  = $codes->issueToken($binding, CarbonImmutable::now()->addMinute(), 3600);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $second);

        (new SendPasswordReset($binding, $first))->handle(app());

        self::assertSame(0, $this->links->count());

        (new SendPasswordReset($binding, $second))->handle(app());

        self::assertSame($second->code, $this->links->lastTokenFor(self::EMAIL));
    }
}
