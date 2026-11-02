<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the keyed digests behind one-time codes: what each digest is
 * made of (a factor code's transaction among them), the key it is made with,
 * and the keys that fail closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeKeys::class)]
#[CoversClass(CodeBinding::class)]
final class CodeKeysTest extends TestCase
{
    /** @var string Application key the keys are derived from when no codes key is set. */
    private const string APP_KEY = 'base64:2fl+Ktvkfl+Fuz4Qp/A75G2RTiWVA/ZoKZvp6fiiM10=';

    /** @var string A codes key of exactly 32 bytes. */
    private const string CODES_KEY = '0123456789abcdef0123456789abcdef';

    /**
     * A sign-in binding's digest is the HMAC-SHA256 of `binding`, the purpose,
     * guard, type, identifier and an empty identity joined by NUL bytes, under
     * a key derived from the application key for bindings: the same on every
     * call, and not the plain digest anyone could recompute.
     *
     * @return void
     */
    public function testASignInBindingsDigestIsAKeyedDigestOfItsParts(): void
    {
        $secret   = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code bindings', self::APP_KEY, true);
        $parts    = implode("\0", ['binding', 'sign_in', 'mobile', 'phone', '+447700900123', '']);
        $expected = hash_hmac('sha256', $parts, $secret);
        $binding  = CodeBinding::signIn('mobile', 'phone', '+447700900123');

        self::assertSame($expected, self::keys()->binding($binding));
        self::assertSame($expected, self::keys()->binding($binding));
        self::assertNotSame(hash('sha256', $parts), $expected);
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $expected);
    }

    /**
     * A verification binding names the identity it is for, as the account
     * attempts name it, so its digest differs from a sign-in's and from another
     * identity's for the same identifier.
     *
     * @return void
     */
    public function testAVerificationBindingNamesItsIdentity(): void
    {
        $ada     = new PlainIdentityFixture(1);
        $ben     = new PlainIdentityFixture(2);
        $secret  = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code bindings', self::APP_KEY, true);
        $binding = CodeBinding::verification('mobile', 'phone', '+447700900123', $ada);

        self::assertSame(AccountAttempts::account($ada), $binding->identity);
        self::assertSame(
            hash_hmac('sha256', implode("\0", ['binding', 'verification', 'mobile', 'phone', '+447700900123', AccountAttempts::account($ada)]), $secret),
            self::keys()->binding($binding),
        );

        $digests = [
            self::keys()->binding($binding),
            self::keys()->binding(CodeBinding::verification('mobile', 'phone', '+447700900123', $ben)),
            self::keys()->binding(CodeBinding::signIn('mobile', 'phone', '+447700900123')),
        ];

        self::assertCount(3, array_unique($digests));
    }

    /**
     * A reset code and a reset link's token are bound to the identifier alone,
     * with no identity, and each under a purpose of its own: neither digest is
     * a sign-in code's, nor the other's, for the same identifier.
     *
     * @return void
     */
    public function testResetBindingsCarryNoIdentityAndAPurposeOfTheirOwn(): void
    {
        $secret = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code bindings', self::APP_KEY, true);
        $code   = CodeBinding::passwordReset('web', 'email', 'ada@example.com');
        $link   = CodeBinding::passwordResetLink('web', 'email', 'ada@example.com');

        self::assertSame(['password_reset', 'web', 'email', 'ada@example.com', ''], [$code->purpose->value, $code->guard, $code->type, $code->identifier, $code->identity]);
        self::assertSame(['password_reset_link', 'web', 'email', 'ada@example.com', ''], [$link->purpose->value, $link->guard, $link->type, $link->identifier, $link->identity]);
        self::assertSame(hash_hmac('sha256', implode("\0", ['binding', 'password_reset', 'web', 'email', 'ada@example.com', '']), $secret), self::keys()->binding($code));
        self::assertSame(hash_hmac('sha256', implode("\0", ['binding', 'password_reset_link', 'web', 'email', 'ada@example.com', '']), $secret), self::keys()->binding($link));

        $digests = [
            self::keys()->binding($code),
            self::keys()->binding($link),
            self::keys()->binding(CodeBinding::signIn('web', 'email', 'ada@example.com')),
        ];

        self::assertCount(3, array_unique($digests));
    }

    /**
     * A change code is bound to the identity and to its change request, so
     * every request, and every identity, has a binding of its own for the same
     * new identifier.
     *
     * @return void
     */
    public function testAnIdentifierChangeBindingNamesItsIdentityAndRequest(): void
    {
        $ada     = new PlainIdentityFixture(1);
        $ben     = new PlainIdentityFixture(2);
        $secret  = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code bindings', self::APP_KEY, true);
        $binding = CodeBinding::identifierChange('web', 'email', 'new@example.com', $ada, 'request-1');

        self::assertSame(['change_identifier', AccountAttempts::account($ada) . "\0request-1"], [$binding->purpose->value, $binding->identity]);
        self::assertSame(
            hash_hmac('sha256', implode("\0", ['binding', 'change_identifier', 'web', 'email', 'new@example.com', AccountAttempts::account($ada), 'request-1']), $secret),
            self::keys()->binding($binding),
        );

        $digests = [
            self::keys()->binding($binding),
            self::keys()->binding(CodeBinding::identifierChange('web', 'email', 'new@example.com', $ada, 'request-2')),
            self::keys()->binding(CodeBinding::identifierChange('web', 'email', 'new@example.com', $ben, 'request-1')),
            self::keys()->binding(CodeBinding::verification('web', 'email', 'new@example.com', $ada)),
        ];

        self::assertCount(4, array_unique($digests));
    }

    /**
     * Rows of a binding differing from the reference in one part.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Codes\CodeBinding}>
     */
    public static function provideOtherBindings(): iterable
    {
        yield from [
            'another guard'      => [CodeBinding::signIn('web', 'phone', '+447700900123')],
            'another type'       => [CodeBinding::signIn('mobile', 'whatsapp', '+447700900123')],
            'another identifier' => [CodeBinding::signIn('mobile', 'phone', '+447700900124')],
            'parts shifted'      => [CodeBinding::signIn('mobile', "phone\0+447700900123", '')],
        ];
    }

    /**
     * Changing any part of the binding changes its digest, and the NUL
     * separators keep parts from running into each other.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $other
     * @return void
     */
    #[DataProvider('provideOtherBindings')]
    public function testEveryPartOfTheBindingCounts(CodeBinding $other): void
    {
        self::assertNotSame(self::keys()->binding(CodeBinding::signIn('mobile', 'phone', '+447700900123')), self::keys()->binding($other));
    }

    /**
     * A code's hash is the HMAC-SHA256 of `code`, the binding digest, the
     * issuance and the code under a key derived separately from the binding
     * key, so the same digits hash differently in another issuance.
     *
     * @return void
     */
    public function testACodesHashIsKeyedSeparatelyAndBoundToItsIssuance(): void
    {
        $secret = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code hashes', self::APP_KEY, true);
        $digest = str_repeat('d', 64);
        $hash   = self::keys()->code($digest, 'issue-1', '123456');

        self::assertSame(hash_hmac('sha256', implode("\0", ['code', $digest, 'issue-1', '123456']), $secret), $hash);
        self::assertNotSame($hash, self::keys()->code($digest, 'issue-2', '123456'));
        self::assertNotSame($hash, self::keys()->code(str_repeat('e', 64), 'issue-1', '123456'));
        self::assertNotSame($hash, self::keys()->code($digest, 'issue-1', '123457'));
    }

    /**
     * A codes key of at least 32 bytes is used in place of the application key,
     * so the digests change with it and not with the application key.
     *
     * @return void
     */
    public function testAConfiguredKeyReplacesTheApplicationKey(): void
    {
        $binding = CodeBinding::signIn('mobile', 'phone', '+447700900123');
        $secret  = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code bindings', self::CODES_KEY, true);
        $keys    = self::keys(self::CODES_KEY);

        self::assertSame(hash_hmac('sha256', implode("\0", ['binding', 'sign_in', 'mobile', 'phone', '+447700900123', '']), $secret), $keys->binding($binding));
        self::assertSame($keys->binding($binding), self::keys(self::CODES_KEY, 'base64:another application key')->binding($binding));
        self::assertNotSame($keys->binding($binding), self::keys()->binding($binding));
    }

    /**
     * An empty codes key, as `env()` returns for a variable set to nothing,
     * falls back to the application key like `null`.
     *
     * @return void
     */
    public function testAnEmptyKeyFallsBackToTheApplicationKey(): void
    {
        $binding = CodeBinding::signIn('mobile', 'phone', '+447700900123');

        self::assertSame(self::keys()->binding($binding), self::keys('')->binding($binding));
        self::keys('')->validate();
    }

    /**
     * Rows of malformed codes keys.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedKeys(): iterable
    {
        yield from [
            'one byte short' => [substr(self::CODES_KEY, 1)],
            'a number'       => [12345678901234567890],
            'a list'         => [[self::CODES_KEY]],
        ];
    }

    /**
     * A codes key that is not a string of at least 32 bytes fails closed.
     *
     * @param  mixed  $key
     * @return void
     */
    #[DataProvider('provideMalformedKeys')]
    public function testRefusesAMalformedKey(mixed $key): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.codes.key must be a string of at least 32 bytes, or null to derive the key from `app.key`.');

        self::keys($key)->validate();
    }

    /**
     * With neither a codes key nor an application key there is nothing to key
     * the codes with.
     *
     * @return void
     */
    public function testRefusesToDigestWithoutAnyKey(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('One-time codes are keyed with `authentication.codes.key`, or the application key when it is not set; set either.');

        self::keys(null, '')->binding(CodeBinding::signIn('mobile', 'phone', '+447700900123'));
    }

    /**
     * A further factor's binding is keyed on its purpose, the guard, the
     * channel's kind, the destination and the identity, as a verification is,
     * and names its session, factor and proof purpose (for an enrolment, its
     * grant) as its transaction, which the key leaves out: an enrolment
     * restarted with a new factor, grant or session keeps its key, and a
     * sign-in's and a step-up's `mfa` challenges share one.
     *
     * @return void
     */
    public function testAFactorBindingIsKeyedOnItsDestinationAndOwner(): void
    {
        $ada     = new PlainIdentityFixture(1);
        $secret  = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code bindings', self::APP_KEY, true);
        $context = hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code contexts', self::APP_KEY, true);
        $signIn  = CodeBinding::factor('mobile', self::factorBinding($ada, Purpose::SIGN_IN));
        $enrol   = CodeBinding::factor('mobile', self::factorBinding($ada, Purpose::ENROLLMENT, 'factor-1', 'grant-1'));

        self::assertSame(
            ['mfa', 'mobile', 'sms', '+447700900123', AccountAttempts::account($ada)],
            [$signIn->purpose->value, $signIn->guard, $signIn->type, $signIn->identifier, $signIn->identity],
        );
        self::assertSame("session-1\0factor-1\0sign_in", $signIn->transaction);
        self::assertSame("session-1\0factor-1\0grant-1", $enrol->transaction);
        self::assertSame(
            hash_hmac('sha256', implode("\0", ['binding', 'mfa', 'mobile', 'sms', '+447700900123', AccountAttempts::account($ada)]), $secret),
            self::keys()->binding($signIn),
        );
        self::assertSame(hash_hmac('sha256', implode("\0", ['context', 'mfa', "session-1\0factor-1\0sign_in"]), $context), self::keys()->context($signIn));

        $restarted = CodeBinding::factor('mobile', self::factorBinding($ada, Purpose::ENROLLMENT, 'factor-2', 'grant-2', 'session-2'));
        $stepUp    = CodeBinding::factor('mobile', self::factorBinding($ada, Purpose::STEP_UP));

        self::assertSame(self::keys()->binding($enrol), self::keys()->binding($restarted));
        self::assertSame(self::keys()->binding($signIn), self::keys()->binding($stepUp));
        self::assertNotSame(self::keys()->binding($signIn), self::keys()->binding($enrol));
        self::assertNotSame(
            self::keys()->binding($signIn),
            self::keys()->binding(CodeBinding::factor('mobile', self::factorBinding(new PlainIdentityFixture(2), Purpose::SIGN_IN))),
        );
        self::assertCount(4, array_unique([self::keys()->context($signIn), self::keys()->context($stepUp), self::keys()->context($enrol), self::keys()->context($restarted)]));
    }

    /**
     * Rows of `[another factor binding]`: one differing from the `mfa` binding
     * of session `session-1` and factor `factor-1` in each part of its
     * transaction.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding}>
     */
    public static function provideOtherTransactions(): iterable
    {
        $ada = new PlainIdentityFixture(1);

        yield from [
            'another session'    => [static fn (): FactorCodeBinding => self::factorBinding($ada, Purpose::SIGN_IN, session: 'session-2')],
            'an integer session' => [static fn (): FactorCodeBinding => self::factorBinding($ada, Purpose::SIGN_IN, session: 1)],
            'another factor'     => [static fn (): FactorCodeBinding => self::factorBinding($ada, Purpose::SIGN_IN, 'factor-2')],
            'a step-up'          => [static fn (): FactorCodeBinding => self::factorBinding($ada, Purpose::STEP_UP)],
        ];
    }

    /**
     * Every part of a factor binding's transaction counts in its digest.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $other
     * @return void
     */
    #[DataProvider('provideOtherTransactions')]
    public function testEveryPartOfTheTransactionCounts(\Closure $other): void
    {
        $binding = CodeBinding::factor('mobile', self::factorBinding(new PlainIdentityFixture(1), Purpose::SIGN_IN));

        self::assertNotSame(self::keys()->context($binding), self::keys()->context(CodeBinding::factor('mobile', $other())));
    }

    /**
     * A binding of any other purpose names no transaction, so it has no
     * transaction digest.
     *
     * @return void
     */
    public function testOtherBindingsHaveNoTransaction(): void
    {
        $ada = new PlainIdentityFixture(1);

        $bindings = [
            CodeBinding::signIn('mobile', 'phone', '+447700900123'),
            CodeBinding::verification('mobile', 'phone', '+447700900123', $ada),
            CodeBinding::passwordReset('web', 'email', 'ada@example.com'),
            CodeBinding::passwordResetLink('web', 'email', 'ada@example.com'),
            CodeBinding::identifierChange('web', 'email', 'ada@example.com', $ada, 'request-1'),
        ];

        foreach ($bindings as $binding) {
            self::assertSame('', $binding->transaction);
            self::assertNull(self::keys()->context($binding));
        }
    }

    /**
     * Build the keys over a codes key and an application key.
     *
     * @param  mixed  $codesKey
     * @param  mixed  $appKey
     * @return \SineMacula\Laravel\Authentication\Codes\CodeKeys
     */
    private static function keys(mixed $codesKey = null, mixed $appKey = self::APP_KEY): CodeKeys
    {
        return new CodeKeys(new Repository(['app' => ['key' => $appKey], 'authentication' => ['codes' => ['key' => $codesKey]]]));
    }

    /**
     * A factor code binding for the identity's text message factor on the
     * `mobile` application.
     *
     * @param  \Tests\Unit\Stubs\PlainIdentityFixture  $identity
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  string  $factor
     * @param  ?string  $grant
     * @param  int|string  $session
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    private static function factorBinding(
        PlainIdentityFixture $identity,
        Purpose $purpose,
        string $factor = 'factor-1',
        ?string $grant = null,
        int|string $session = 'session-1',
    ): FactorCodeBinding {
        return new FactorCodeBinding(new ProofBinding($identity, 'mobile', $session, $purpose), $factor, new Channel(ChannelKind::SMS, '+447700900123'), $grant);
    }
}
