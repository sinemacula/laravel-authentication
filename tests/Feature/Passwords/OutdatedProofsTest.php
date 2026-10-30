<?php

declare(strict_types = 1);

namespace Tests\Feature\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Guards\JwtGuards;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\OutdatedProofs;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use SineMacula\Laravel\Authentication\Passwords\ResetRecipient;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MappedEmailIdentity;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\TestCase;

/**
 * Feature tests of what a new password outdates: once a reset or a change
 * commits, no other reset link or code, and no sign-in code, for the identity's
 * identifiers works, through any guard that can return it, so whoever obtained
 * one before cannot take the account back; a link or code for another
 * identity's identifier keeps working.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OutdatedProofs::class)]
#[CoversClass(ResetRecipient::class)]
#[CoversClass(PasswordWriter::class)]
#[CoversClass(JwtGuards::class)]
final class OutdatedProofsTest extends TestCase
{
    use InteractsWithPasswordResets;

    /** @var string The password whoever holds an outdated link or code would set. */
    private const string TAKEOVER_PASSWORD = 'a takeover passphrase';

    /**
     * A reset with a link through one guard ends the identity's link for
     * another guard and its reset code for another of its identifiers, and
     * leaves another identity's link alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetEndsEveryOtherLinkAndCodeOfTheIdentity(): void
    {
        self::seedResettable();
        self::seedPasswordIdentity('grace@example.test');

        $web   = self::issueToken('web');
        $admin = self::issueToken('admin');
        $code  = self::issueCode('web', 'phone', self::PHONE);
        $grace = self::issue(CodeBinding::passwordResetLink('web', 'email', 'grace@example.test'), true);

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $web, 'password' => self::NEW_PASSWORD])->status);

        self::assertSame(ResetStatus::INVALID, $this->passwords('admin')->reset(['email' => self::EMAIL, 'token' => $admin, 'password' => self::TAKEOVER_PASSWORD])->status);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->resetWithCode('phone', self::takeover('phone', self::PHONE, $code))->status);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, self::storedPassword(PasswordIdentity::query()->where('email', self::EMAIL)->value('password'))));

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => 'grace@example.test', 'token' => $grace, 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * A change of password ends every reset link and code issued for the
     * identity's identifiers before it, through every guard, in its own
     * transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeEndsEveryLinkAndCodeIssuedBeforeIt(): void
    {
        $identity = self::seedResettable();

        $web   = self::issueToken('web');
        $admin = self::issueToken('admin');
        $code  = self::issueCode('admin', 'phone', self::PHONE);

        self::assertTrue($this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
        self::assertSame(0, DB::table('one_time_codes')->count());

        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $web, 'password' => self::TAKEOVER_PASSWORD])->status);
        self::assertSame(ResetStatus::INVALID, $this->passwords('admin')->reset(['email' => self::EMAIL, 'token' => $admin, 'password' => self::TAKEOVER_PASSWORD])->status);
        self::assertSame(ResetStatus::INVALID, $this->passwords('admin')->resetWithCode('phone', self::takeover('phone', self::PHONE, $code))->status);
    }

    /**
     * A reset and a change end the sign-in codes waiting for the identity's
     * identifiers, through every guard that can return it, since each would
     * open a session after the ones the new password ended; another identity's
     * sign-in code keeps working.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetAndAChangeEndTheSignInCodesOfTheIdentity(): void
    {
        $identity = self::seedResettable();

        self::seedPasswordIdentity('grace@example.test');

        $email = self::issue(CodeBinding::signIn('admin', 'email', self::EMAIL), false);
        $phone = self::issue(CodeBinding::signIn('web', 'phone', self::PHONE), false);
        $grace = self::issue(CodeBinding::signIn('web', 'email', 'grace@example.test'), false);

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => self::issueToken('web'), 'password' => self::NEW_PASSWORD])->status);
        self::assertSame(CodeCheck::INVALID, self::check(CodeBinding::signIn('admin', 'email', self::EMAIL), $email));
        self::assertSame(CodeCheck::INVALID, self::check(CodeBinding::signIn('web', 'phone', self::PHONE), $phone));

        $email = self::issue(CodeBinding::signIn('web', 'email', self::EMAIL), false);

        self::assertTrue($this->passwords()->set($identity->fresh() ?? $identity, self::TAKEOVER_PASSWORD, PasswordFlow::CHANGE)->set);
        self::assertSame(CodeCheck::INVALID, self::check(CodeBinding::signIn('web', 'email', self::EMAIL), $email));
        self::assertSame(CodeCheck::ACCEPTED, self::check(CodeBinding::signIn('web', 'email', 'grace@example.test'), $grace));
    }

    /**
     * A registration ends no session, so it leaves the identity's sign-in codes
     * working, while its reset links, through every guard, are ended as any new
     * password ends them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARegistrationKeepsTheSignInCodesOfTheIdentity(): void
    {
        $identity = self::seedResettable(['password' => null]);
        $code     = self::issue(CodeBinding::signIn('web', 'email', self::EMAIL), false);
        $web      = self::issueToken('web');
        $admin    = self::issueToken('admin');

        self::assertTrue($this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::REGISTRATION)->set);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $web, 'password' => self::TAKEOVER_PASSWORD])->status);
        self::assertSame(ResetStatus::INVALID, $this->passwords('admin')->reset(['email' => self::EMAIL, 'token' => $admin, 'password' => self::TAKEOVER_PASSWORD])->status);
        self::assertSame(CodeCheck::ACCEPTED, self::check(CodeBinding::signIn('web', 'email', self::EMAIL), $code));
    }

    /**
     * A guard whose provider reads another table binds its links to another
     * identity: the one holding the same address there keeps its link when this
     * identity's password changes, and resets with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardOverAnotherModelKeepsItsProofs(): void
    {
        $this->createSessionTables();

        try {
            $other    = $this->seedIdentity(self::EMAIL);
            $identity = self::seedResettable();
            $token    = self::issueToken('plain');

            self::assertTrue($this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
            self::assertSame(ResetStatus::RESET, $this->passwords('plain')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::TAKEOVER_PASSWORD])->status);
            self::assertTrue(app(Hasher::class)->check(self::TAKEOVER_PASSWORD, self::storedPassword($other->fresh()?->password)));
        } finally {
            $this->dropSessionTables();
        }
    }

    /**
     * The identifiers are read from the identity's stored row, not from the
     * model given: one loaded with only some columns still has the links and
     * codes of every identifier its row holds ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAModelLoadedWithSomeColumnsOutdatesEveryIdentifierOfItsRow(): void
    {
        $seeded  = self::seedResettable();
        $token   = self::issueToken('web');
        $code    = self::issueCode('web', 'phone', self::PHONE);
        $partial = PasswordIdentity::query()->select(['id', 'password'])->findOrFail($seeded->getKey());

        self::assertTrue($this->passwords()->set($partial, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
        self::assertSame(0, DB::table('one_time_codes')->count());
        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::TAKEOVER_PASSWORD])->status);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->resetWithCode('phone', self::takeover('phone', self::PHONE, $code))->status);
    }

    /**
     * A model older than its row outdates the identifiers the row holds now:
     * the address it was changed to by another path has its link ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAModelOlderThanItsRowOutdatesTheIdentifiersTheRowHolds(): void
    {
        $stale = self::seedResettable();

        DB::table('password_identities')->update(['email' => 'ada@moved.example.test']);

        $token = self::issue(CodeBinding::passwordResetLink('web', 'email', 'ada@moved.example.test'), true);

        self::assertTrue($this->passwords()->set($stale, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => 'ada@moved.example.test', 'token' => $token, 'password' => self::TAKEOVER_PASSWORD])->status);
    }

    /**
     * An identity with no identifier of one type still has the reset codes of
     * its other types ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierTheIdentityLacksSkipsOnlyItsType(): void
    {
        $identity = self::seedResettable(['email' => null]);
        $code     = self::issueCode('web', 'phone', self::PHONE);

        self::assertTrue($this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
        self::assertSame(ResetStatus::INVALID, $this->passwords()->resetWithCode('phone', self::takeover('phone', self::PHONE, $code))->status);
    }

    /**
     * A guard whose passwords are identified by a type with no normaliser has
     * its reset links for that identifier ended too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardsOwnPasswordIdentifierIsOutdatedToo(): void
    {
        config()->set('auth.guards.nicknames', [
            'driver'   => 'jwt',
            'provider' => 'password_identities',
            'audience' => ['methods' => ['password']],
            'sign_in'  => ['password_identifier' => 'nickname'],
        ]);

        $identity = self::seedResettable(['nickname' => 'ada']);
        $token    = self::issue(CodeBinding::passwordResetLink('nicknames', 'nickname', 'ada'), true);

        self::assertTrue($this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
        self::assertSame(ResetStatus::INVALID, $this->passwords('nicknames')->reset(['nickname' => 'ada', 'token' => $token, 'password' => self::TAKEOVER_PASSWORD])->status);
    }

    /**
     * A change rolled back with the caller's transaction leaves every link and
     * code as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeRolledBackOutdatesNothing(): void
    {
        $identity = self::seedResettable();
        $token    = self::issueToken('web');

        DB::beginTransaction();

        self::assertTrue($this->passwords()->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);

        DB::rollBack();

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * An identity that cannot report verification is read by the attribute
     * named after each type, and a type it has no attribute for is skipped,
     * even while Eloquent refuses to read a missing attribute.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutVerificationOutdatesTheLinksOfItsAttributes(): void
    {
        $this->createSessionTables();

        Model::preventAccessingMissingAttributes();

        try {
            $this->seedIdentity(self::EMAIL);

            $token    = self::issueToken('plain');
            $identity = IntegrationIdentity::query()->where('email', self::EMAIL)->sole();

            self::assertTrue($this->passwords('plain')->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
            self::assertSame(ResetStatus::INVALID, $this->passwords('plain')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::TAKEOVER_PASSWORD])->status);
        } finally {
            Model::preventAccessingMissingAttributes(false);

            $this->dropSessionTables();
        }
    }

    /**
     * An identity that cannot report verification and stores its address in
     * another case has the links of that address, in canonical form, ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutVerificationStoringAnotherCaseOutdatesItsLinks(): void
    {
        $this->createSessionTables();

        try {
            $identity = $this->seedIdentity('Ada@Example.test');
            $token    = self::issueToken('lookalike_plain');

            self::assertTrue($this->passwords('lookalike_plain')->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
            self::assertSame(0, DB::table('one_time_codes')->count());
            self::assertSame(ResetStatus::INVALID, $this->passwords('lookalike_plain')->reset(self::takeover('email', self::EMAIL, $token, 'token'))->status);
        } finally {
            $this->dropSessionTables();
        }
    }

    /**
     * An identity that reports its email address from a column of another name
     * has that address's links outdated, and a type it cannot report at all
     * (its verification throws a `LogicException` for it) is skipped.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityReportingItsIdentifiersItselfOutdatesTheLinksOfThoseItHas(): void
    {
        $identity = self::seedMappedIdentity();

        try {
            $token = self::issueToken('mapped');

            self::assertTrue($this->passwords('mapped')->set($identity, self::NEW_PASSWORD, PasswordFlow::CHANGE)->set);
            self::assertSame(ResetStatus::INVALID, $this->passwords('mapped')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::TAKEOVER_PASSWORD])->status);
            self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, self::storedPassword(MappedEmailIdentity::query()->sole()->password)));
        } finally {
            self::dropMappedIdentities();
        }
    }

    /**
     * A normaliser that cannot be built fails the change closed, rolling the
     * new password back, instead of leaving its type's links working.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMisconfiguredNormaliserFailsTheChangeClosed(): void
    {
        $identity = self::seedResettable();
        $stored   = (string) $identity->password;

        config()->set('authentication.identifiers.normalisers.phone', \stdClass::class);

        try {
            $this->passwords()->set($identity->fresh() ?? $identity, self::NEW_PASSWORD, PasswordFlow::CHANGE);
            self::fail('A change with a misconfigured normaliser was made.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('The identifier normaliser for [phone]', $exception->getMessage());
        }

        self::assertSame($stored, PasswordIdentity::query()->value('password'));
    }

    /**
     * The input of a reset with the code, or the link's token, that would set
     * the takeover password.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @param  string  $proof
     * @param  string  $field
     * @return array<string, string>
     */
    private static function takeover(string $type, string $identifier, string $proof, string $field = 'code'): array
    {
        return [$type => $identifier, $field => $proof, 'password' => self::TAKEOVER_PASSWORD];
    }

    /**
     * The stored password hash, which must be a string.
     *
     * @param  mixed  $hash
     * @return string
     */
    private static function storedPassword(mixed $hash): string
    {
        self::assertIsString($hash);

        return $hash;
    }

    /**
     * Check the code against the binding now, as a sign-in would.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $code
     * @return \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck
     *
     * @throws \Throwable
     */
    private static function check(CodeBinding $binding, string $code): CodeCheck
    {
        return app(OneTimeCodes::class)->check($binding, $code, CarbonImmutable::now());
    }

    /**
     * Issue a reset code for the identifier on the guard, directly.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @return string
     *
     * @throws \Throwable
     */
    private static function issueCode(string $guard, string $type, string $identifier): string
    {
        return self::issue(CodeBinding::passwordReset($guard, $type, $identifier), false);
    }

    /**
     * Issue the binding's token or code, directly, and return it.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  bool  $token
     * @return string
     *
     * @throws \Throwable
     */
    private static function issue(CodeBinding $binding, bool $token): string
    {
        $codes  = app(OneTimeCodes::class);
        $issued = $token ? $codes->issueToken($binding, CarbonImmutable::now(), 3600) : $codes->issue($binding, CarbonImmutable::now());

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued->code;
    }
}
