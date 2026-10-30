<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\ResetRecipient;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Passwords\SendPasswordReset;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Feature tests of who may reset a password: a machine, an inactive identity,
 * an unverified identifier on a guard that requires verified ones, no one, and
 * a holder found only by a look-alike are sent nothing, and a live token for
 * them resets nothing and stays unspent.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetRecipient::class)]
#[CoversClass(SendPasswordReset::class)]
#[CoversClass(ResetSubmissions::class)]
final class ResetRecipientTest extends TestCase
{
    use InteractsWithPasswordResets;

    /**
     * Rows of an identity that may not reset its password, and the reason the
     * refusal reports: a machine, an inactive identity, and an unverified
     * identifier on a guard that requires verified ones.
     *
     * @return iterable<string, array{0: string, 1: \Closure(): mixed, 2: string}>
     */
    public static function provideIneligibleIdentities(): iterable
    {
        yield from [
            'a machine'            => ['machines', static fn (): mixed => self::seedMachine(), 'machine_identity'],
            'an inactive identity' => ['web', static fn (): mixed => self::seedResettable(['is_active' => false]), 'identity_inactive'],
            'an unverified email'  => ['console', static fn (): mixed => self::seedResettable(['email_verified_at' => null]), 'identifier_unverified'],
            'no one'               => ['web', static fn (): null => null, 'invalid_credentials'],
            'a look-alike holder'  => ['lookalike', static fn (): mixed => self::seedResettable(['email' => 'ada@examplé.test']), 'invalid_credentials'],
        ];
    }

    /**
     * Nothing is sent to an identity that may not reset its password, and a
     * reset with a live token for it is `invalid`, reported with why, and
     * leaves the token unspent.
     *
     * @param  string  $guard
     * @param  \Closure(): mixed  $seed
     * @param  string  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIneligibleIdentities')]
    public function testAnIdentityThatMayNotResetGetsNothing(string $guard, \Closure $seed, string $reason): void
    {
        $seed();

        $this->passwords($guard)->sendResetLink(['email' => self::EMAIL]);
        app()->terminate();

        self::assertSame(0, $this->links->count());

        DB::table('one_time_codes')->delete();

        $token = self::issueToken($guard);

        $this->recordEvents([AuthenticationFailed::class, PasswordSet::class]);

        self::assertSame(ResetStatus::INVALID, $this->passwords($guard)->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason->value);
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * `ResetRecipient` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ResetRecipient::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ResetRecipient::class, $instance);
    }

    /**
     * An identity that cannot report its identifiers verified is found by the
     * model attribute named after the type, compared in canonical form: it is
     * sent the link and resets with it, even on a guard that requires verified
     * identifiers, which it cannot answer.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutVerificationResetsByItsAttribute(): void
    {
        $this->createSessionTables();

        try {
            $identity = $this->seedIdentity(self::EMAIL);

            foreach (['plain', 'plain_verified'] as $guard) {

                $this->passwords($guard)->sendResetLink(['email' => ' Ada@Example.test']);
                app()->terminate();

                $link = $this->links->sent()[0] ?? null;

                self::assertNotNull($link);
                self::assertTrue($identity->is($link->identity));

                $result = $this->passwords($guard)->reset(['email' => self::EMAIL, 'token' => $link->token(), 'password' => self::NEW_PASSWORD]);

                self::assertSame(ResetStatus::RESET, $result->status, $guard);

                $this->links->forget();

                self::freezeClock(CarbonImmutable::parse(self::NOW)->addMinutes(5));
            }
        } finally {
            $this->dropSessionTables();
        }
    }

    /**
     * An identity that cannot report verification and stores its address in
     * another case holds the address in canonical form: found by a provider
     * that matches any case, it is sent the link and resets with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutVerificationStoringAnotherCaseResets(): void
    {
        $this->createSessionTables();

        try {
            $identity = $this->seedIdentity('Ada@Example.test');

            $this->passwords('lookalike_plain')->sendResetLink(['email' => self::EMAIL]);
            app()->terminate();

            $link = $this->links->sent()[0] ?? null;

            self::assertNotNull($link);
            self::assertTrue($identity->is($link->identity));

            $result = $this->passwords('lookalike_plain')->reset(['email' => self::EMAIL, 'token' => $link->token(), 'password' => self::NEW_PASSWORD]);

            self::assertSame(ResetStatus::RESET, $result->status);
        } finally {
            $this->dropSessionTables();
        }
    }

    /**
     * An identity that reports its email address through its verification, from
     * a column not named after the type, holds the address: it is sent the link
     * and resets with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityReportingItsAddressFromAnotherColumnResets(): void
    {
        $identity = self::seedMappedIdentity();

        try {
            $this->passwords('mapped')->sendResetLink(['email' => ' Ada@Example.test']);
            app()->terminate();

            $link = $this->links->sent()[0] ?? null;

            self::assertNotNull($link);
            self::assertTrue($identity->is($link->identity));

            $result = $this->passwords('mapped')->reset(['email' => self::EMAIL, 'token' => $link->token(), 'password' => self::NEW_PASSWORD]);

            self::assertSame(ResetStatus::RESET, $result->status);
        } finally {
            self::dropMappedIdentities();
        }
    }

    /**
     * An identity that cannot report verification, found only by a look-alike
     * of its stored address, does not hold the address: it is sent nothing, and
     * a live token for the address resets nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALookAlikeHolderWithoutVerificationGetsNothing(): void
    {
        $this->createSessionTables();

        try {
            $this->seedIdentity('ada@examplé.test');

            $this->passwords('lookalike_plain')->sendResetLink(['email' => self::EMAIL]);
            app()->terminate();

            self::assertSame(0, $this->links->count());

            DB::table('one_time_codes')->delete();

            $token = self::issueToken('lookalike_plain');

            $this->recordEvents([AuthenticationFailed::class]);

            $result = $this->passwords('lookalike_plain')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);

            self::assertSame(ResetStatus::INVALID, $result->status);
            self::assertSame('invalid_credentials', $this->recordedEvent(AuthenticationFailed::class)->reason->value);
        } finally {
            $this->dropSessionTables();
        }
    }

    /**
     * An identity the provider returns that is not an Eloquent model cannot
     * have its password set, so it is sent nothing and resets nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsNotAModelGetsNothing(): void
    {
        $provider = \Mockery::mock(IdentityProvider::class);

        $provider->shouldReceive('retrieveByCredentials')->andReturn(new PlainIdentityFixture(1));

        Auth::provider('plain-fixture', static fn (): IdentityProvider => $provider);

        config()->set('auth.providers.plain_fixture', ['driver' => 'plain-fixture']);
        config()->set('auth.guards.plain_fixture', ['driver' => 'jwt', 'provider' => 'plain_fixture', 'audience' => ['methods' => ['password']]]);

        $this->passwords('plain_fixture')->sendResetLink(['email' => self::EMAIL]);
        app()->terminate();

        self::assertSame(0, $this->links->count());

        DB::table('one_time_codes')->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->passwords('plain_fixture')->reset(['email' => self::EMAIL, 'token' => self::issueToken('plain_fixture'), 'password' => self::NEW_PASSWORD]);

        self::assertSame(ResetStatus::INVALID, $result->status);
        self::assertSame('invalid_credentials', $this->recordedEvent(AuthenticationFailed::class)->reason->value);
    }
}
