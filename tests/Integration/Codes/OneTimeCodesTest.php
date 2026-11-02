<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\DeliveryRefusal;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use Tests\Concerns\InteractsWithCodes;
use Tests\Fixtures\Database\LockMarkingSQLiteGrammar;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Integration tests for the one-time code engine against the shipped table:
 * issuing codes and reset link tokens, checking codes and tokens against their
 * challenge, expiry, the attempt limit and single use, each on the write
 * connection, and what a check does when another request changes the code
 * between its read and its writes. How deliveries are written (the cooldown,
 * resends, the delivery window and its cap) is `ChallengeDeliveriesTest`'s.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(OneTimeCodes::class)]
#[CoversClass(IssuedCode::class)]
final class OneTimeCodesTest extends TestCase
{
    use InteractsWithCodes;

    /** @var string Number the codes are bound to. */
    private const string PHONE = '+447700900123';

    /** @var \Carbon\CarbonImmutable The moment every test starts at. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        CarbonImmutable::setTestNow($this->now);
    }

    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Issuing for a fresh binding stores one row under the binding's keyed
     * digest: its purpose and guard, a new issuance, the keyed hash of the code
     * in that issuance, no attempts, and when it was issued and expires. The
     * row holds neither the code nor the identifier.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuingStoresOnlyTheKeyedHashOfTheCode(): void
    {
        $binding = self::binding();
        $issued  = self::codes()->issue($binding, $this->now);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertMatchesRegularExpression('/^[0-9]{6}$/', $issued->code());
        self::assertTrue($this->now->addSeconds(600)->equalTo($issued->expiresAt));

        $row = (array) DB::table('one_time_codes')->sole();

        self::assertSame(self::bindingDigest($binding), $row['id']);
        self::assertSame(['sign_in', 'mobile', $issued->issueId, 0], [$row['purpose'], $row['guard'], $row['issue_id'], (int) $row['attempts']]);
        self::assertSame(self::codeHash($binding, $issued->issueId, $issued->code()), $row['code_hash']);
        self::assertSame(['2026-04-06 12:00:00', '2026-04-06 12:10:00', null], [$row['issued_at'], $row['expires_at'], $row['consumed_at']]);

        foreach ($row as $value) {
            self::assertStringNotContainsString(self::PHONE, (string) $value);
            self::assertNotSame($issued->code(), $value);
        }
    }

    /**
     * A used code stays invalid once it has expired, or the check that used it
     * took its last attempt: it is neither expired nor exhausted.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAUsedCodeStaysInvalid(): void
    {
        config()->set('authentication.codes.max_attempts', 1);

        $binding = self::binding();
        $issued  = self::issued($binding);

        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now));
        self::assertSame(CodeCheck::INVALID, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now));
        self::assertSame(CodeCheck::INVALID, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now->addSeconds(600)));
    }

    /**
     * The configured length and lifetime apply to the codes issued.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuesCodesOfTheConfiguredLengthAndLifetime(): void
    {
        config()->set('authentication.codes.length', 10);
        config()->set('authentication.codes.ttl_seconds', '120');

        $issued = self::codes()->issue(self::binding(), $this->now);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertMatchesRegularExpression('/^[0-9]{10}$/', $issued->code());
        self::assertSame('2026-04-06 12:02:00', DB::table('one_time_codes')->value('expires_at'));
    }

    /**
     * A code issued first for a request of its own is written by the insert
     * alone, with nothing read before it, at the configured length and
     * lifetime; it is capped by its delivery window as `issue()`'s is.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFirstIssueInsertsBeforeItReadsAndIsCappedByItsWindow(): void
    {
        config()->set('authentication.codes.length', 8);

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = strtolower($query->sql);
        });

        $issued = self::codes()->issueFirst(self::binding(), $this->now);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertMatchesRegularExpression('/^[0-9]{8}$/', $issued->code());
        self::assertTrue($this->now->addSeconds(600)->equalTo($issued->expiresAt));
        self::assertCount(1, $statements);
        self::assertStringStartsWith('insert', $statements[0]);

        $late = self::codes()->issueFirst(self::binding(), $this->now->addSeconds(1500));

        self::assertInstanceOf(IssuedCode::class, $late);
        self::assertTrue($this->now->addSeconds(1800)->equalTo($late->expiresAt));
    }

    /**
     * A code never outlives the delivery window it was delivered in, while a
     * token keeps the lifetime it was issued with, whatever is left of its
     * window.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOnlyACodeIsCutShortByItsDeliveryWindow(): void
    {
        $late = $this->now->addSeconds(1500);

        $this->issued(self::binding());
        self::assertInstanceOf(IssuedCode::class, self::codes()->issueToken(self::linkBinding(), $this->now, 900));

        $code  = self::codes()->issue(self::binding(), $late);
        $token = self::codes()->issueToken(self::linkBinding(), $late, 900);

        self::assertInstanceOf(IssuedCode::class, $code);
        self::assertInstanceOf(IssuedCode::class, $token);
        self::assertTrue($this->now->addSeconds(1800)->equalTo($code->expiresAt));
        self::assertTrue($late->addSeconds(900)->equalTo($token->expiresAt));
    }

    /**
     * A check reads the challenge without a lock unless asked to lock it until
     * the caller's transaction ends.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckLocksTheChallengeOnlyWhenAsked(): void
    {
        $connection = DB::connection();

        if ($connection->getDriverName() === 'sqlite') {
            $connection->setQueryGrammar(new LockMarkingSQLiteGrammar($connection));
        }

        $issued = $this->issued(self::binding(), '123456');
        $reads  = [];

        $connection->listen(static function (QueryExecuted $query) use (&$reads): void {
            if (!str_starts_with(strtolower($query->sql), 'select')) {
                return;
            }

            $reads[] = str_contains($query->sql, 'for update');
        });

        self::assertSame(CodeCheck::WRONG, self::codes()->check(self::binding(), $issued->challengeId, '654321', $this->now));
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check(self::binding(), $issued->challengeId, '123456', $this->now, true));
        self::assertSame([false, true], $reads);
    }

    /**
     * Codes are drawn uniformly over every digit string of their length,
     * leading zeros included: over 1,000 codes, each digit appears at each
     * position about a tenth of the time.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testDrawsCodesUniformly(): void
    {
        $engine = self::codes();
        $counts = array_fill(0, 10, 0);

        for ($draw = 0; $draw < 1000; $draw++) {

            $issued = $engine->issue(self::binding(), $this->now->addSeconds($draw * 1800));

            self::assertInstanceOf(IssuedCode::class, $issued);
            self::assertSame(6, strlen($issued->code()));

            foreach (str_split($issued->code()) as $digit) {
                $counts[(int) $digit]++;
            }
        }

        foreach ($counts as $digit => $count) {
            self::assertGreaterThan(450, $count, "digit {$digit}");
            self::assertLessThan(750, $count, "digit {$digit}");
        }
    }

    /**
     * The right code is accepted once: the check uses it up, and every later
     * check of it, right or wrong, is invalid.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheRightCodeIsAcceptedOnce(): void
    {
        $binding = self::binding();
        $issued  = self::issued($binding);

        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now));
        self::assertSame('2026-04-06 12:00:00', DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(1, self::attempts());
        self::assertSame(CodeCheck::INVALID, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now));
        self::assertSame(CodeCheck::INVALID, self::codes()->check($binding, self::challenge(), '000000', $this->now));
        self::assertSame(1, self::attempts());
    }

    /**
     * Each check counts one attempt before it compares, so wrong codes use the
     * code's attempts up; once used up, even the right code is refused as
     * exhausted, without counting further.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testWrongCodesUseUpTheAttempts(): void
    {
        config()->set('authentication.codes.max_attempts', 3);

        $binding = self::binding();
        $issued  = self::issued($binding, '123456');

        foreach (['000000', '000001', '000002'] as $attempt => $wrong) {
            self::assertSame(CodeCheck::WRONG, self::codes()->check($binding, self::challenge(), $wrong, $this->now));
            self::assertSame($attempt + 1, self::attempts());
        }

        self::assertSame(CodeCheck::EXHAUSTED, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now));
        self::assertSame(3, self::attempts());
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * The last attempt left can still accept the right code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheLastAttemptCanStillAccept(): void
    {
        config()->set('authentication.codes.max_attempts', 2);

        $binding = self::binding();
        $issued  = self::issued($binding, '123456');

        self::assertSame(CodeCheck::WRONG, self::codes()->check($binding, self::challenge(), '654321', $this->now));
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now));
    }

    /**
     * A code works until the second before it expires, and from the second it
     * expires is refused as expired, without counting an attempt; an expired
     * code that also used up its attempts says expired.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeExpiresFromTheSecondItsLifetimeEnds(): void
    {
        config()->set('authentication.codes.max_attempts', 1);

        $binding = self::binding();
        $issued  = self::issued($binding, '123456');

        self::assertSame(CodeCheck::EXPIRED, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now->addSeconds(600)));
        self::assertSame(0, self::attempts());
        self::assertSame(CodeCheck::WRONG, self::codes()->check($binding, self::challenge(), '000000', $this->now->addSeconds(599)));
        self::assertSame(CodeCheck::EXHAUSTED, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now->addSeconds(599)));
        self::assertSame(CodeCheck::EXPIRED, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now->addSeconds(600)));
    }

    /**
     * Rows of bindings that differ from the one the code was issued for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Codes\CodeBinding}>
     */
    public static function provideOtherBindings(): iterable
    {
        yield from [
            'another guard'      => [CodeBinding::signIn('web', 'phone', self::PHONE)],
            'another type'       => [CodeBinding::signIn('mobile', 'whatsapp', self::PHONE)],
            'another identifier' => [CodeBinding::signIn('mobile', 'phone', '+447700900124')],
            'verification'       => [CodeBinding::verification('mobile', 'phone', self::PHONE, new PlainIdentityFixture(1))],
        ];
    }

    /**
     * A code works only for the binding it was issued for: checked for any
     * other guard, type, identifier or purpose it is invalid and counts nothing
     * against the code.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $other
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideOtherBindings')]
    public function testACodeWorksOnlyForItsBinding(CodeBinding $other): void
    {
        $issued = self::issued(self::binding());

        self::assertSame(CodeCheck::INVALID, self::codes()->check($other, self::challenge(), $issued->code(), $this->now));
        self::assertSame(0, self::attempts());
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check(self::binding(), self::challenge(), $issued->code(), $this->now));
    }

    /**
     * A resend that draws the very digits of the code it replaces still
     * replaces it: the old issuance is no longer current, so its delivery is
     * skipped, and the code works once, for the new issuance.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendOfTheSameDigitsIsANewIssuance(): void
    {
        $binding = self::binding();
        $codes   = self::sequence(['424242', '424242']);
        $first   = $codes->issue($binding, $this->now);
        $later   = $this->now->addSeconds(60);
        $second  = $codes->issue($binding, $later);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $second);
        self::assertSame($first->code(), $second->code());
        self::assertNotSame(self::codeHash($binding, $first->issueId, '424242'), DB::table('one_time_codes')->value('code_hash'));
        self::assertFalse($codes->isCurrent($binding, $first->issueId, $later));
        self::assertTrue($codes->isCurrent($binding, $second->issueId, $later));
        self::assertSame(CodeCheck::ACCEPTED, $codes->check($binding, self::challenge(), '424242', $later));
        self::assertSame(CodeCheck::INVALID, $codes->check($binding, self::challenge(), '424242', $later));
    }

    /**
     * A check that read an issuance a resend replaced, even with the same
     * digits, before it could count its attempt never compares: it is invalid,
     * and the new issuance is untouched and still accepts the code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckOverTakenByAResendOfTheSameDigitsIsInvalid(): void
    {
        $binding = self::binding();
        $codes   = self::sequence(['424242', '424242']);
        $later   = $this->now->addSeconds(60);

        $codes->issue($binding, $this->now);

        $challenge = self::challenge();

        $this->afterTheCheckReads(static function () use ($codes, $binding, $later): void {
            $codes->issue($binding, $later);
        });

        self::assertSame(CodeCheck::INVALID, $codes->check($binding, $challenge, '424242', $later));
        self::assertSame(0, self::attempts());
        self::assertSame(CodeCheck::ACCEPTED, $codes->check($binding, self::challenge(), '424242', $later));
    }

    /**
     * A check that counted its attempt on an issuance and then finds it
     * replaced by a resend of the same digits never uses the replacement up: it
     * is wrong, and the new issuance, which keeps the attempt the check
     * counted, stays unused and still accepts the code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckThatCountedItsAttemptNeverUsesUpAResendOfTheSameDigits(): void
    {
        $binding = self::binding();
        $codes   = self::sequence(['424242', '424242']);
        $later   = $this->now->addSeconds(60);

        $codes->issue($binding, $this->now);

        $this->afterTheAttemptIsCounted(static function () use ($codes, $binding, $later): void {
            $codes->issue($binding, $later);
        });

        self::assertSame(CodeCheck::WRONG, $codes->check($binding, self::challenge(), '424242', $later));
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame(1, self::attempts());
        self::assertSame(CodeCheck::ACCEPTED, $codes->check($binding, self::challenge(), '424242', $later));
    }

    /**
     * Rows of `[change another request makes after the check reads, answer]`: a
     * check whose attempt cannot be counted answers from a fresh read of the
     * issuance it read: exhausted or expired when it now is, invalid when it
     * was used.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck}>
     */
    public static function provideConcurrentChanges(): iterable
    {
        yield from [
            'attempts used up' => [['attempts' => 5], CodeCheck::EXHAUSTED],
            'expired'          => [['expires_at' => '2026-04-06 12:00:00'], CodeCheck::EXPIRED],
            'used'             => [['consumed_at' => '2026-04-06 12:00:00'], CodeCheck::INVALID],
            'deleted'          => [[], CodeCheck::INVALID],
        ];
    }

    /**
     * A check whose attempt increment matches no row never compares or accepts,
     * even with the right code.
     *
     * @param  array<string, mixed>  $change
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck  $answer
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideConcurrentChanges')]
    public function testACheckThatCannotCountItsAttemptNeverAccepts(array $change, CodeCheck $answer): void
    {
        $binding = self::binding();
        $issued  = self::issued($binding);

        $challenge = self::challenge();

        $this->afterTheCheckReads(static function () use ($change): void {
            $change === [] ? DB::table('one_time_codes')->delete() : DB::table('one_time_codes')->update($change);
        });

        self::assertSame($answer, self::codes()->check($binding, $challenge, $issued->code(), $this->now));
        self::assertNotSame('2026-04-06 12:00:01', DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * Of two checks of the right code, only the one that uses the issuance up
     * is accepted: one that counted its attempt but finds the code used by the
     * time it would use it is wrong.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOnlyTheCheckThatUsesTheCodeUpIsAccepted(): void
    {
        $binding = self::binding();
        $issued  = self::issued($binding);

        $this->afterTheAttemptIsCounted(static function (): void {
            DB::table('one_time_codes')->update(['consumed_at' => '2026-04-06 11:59:59']);
        });

        self::assertSame(CodeCheck::WRONG, self::codes()->check($binding, self::challenge(), $issued->code(), $this->now));
        self::assertSame('2026-04-06 11:59:59', DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * A binding nothing was issued for has no code to accept.
     *
     * @return void
     */
    public function testABindingWithNoCodeAcceptsNothing(): void
    {
        self::assertSame(CodeCheck::INVALID, self::codes()->check(self::binding(), self::challenge(), '123456', $this->now));
        self::assertSame(0, DB::table('one_time_codes')->count());
    }

    /**
     * An issuance is current while it is the binding's live code, unused and
     * unexpired, and stops being current when it is used, replaced or expires,
     * or was never issued.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTellsWhetherAnIssuanceIsCurrent(): void
    {
        $binding = self::binding();
        $issued  = self::issued($binding);

        self::assertTrue(self::codes()->isCurrent($binding, $issued->issueId, $this->now->addSeconds(599)));
        self::assertFalse(self::codes()->isCurrent($binding, $issued->issueId, $this->now->addSeconds(600)));
        self::assertFalse(self::codes()->isCurrent($binding, 'another-issuance', $this->now));
        self::assertFalse(self::codes()->isCurrent(CodeBinding::signIn('web', 'phone', self::PHONE), $issued->issueId, $this->now));

        self::codes()->check($binding, self::challenge(), $issued->code(), $this->now);

        self::assertFalse(self::codes()->isCurrent($binding, $issued->issueId, $this->now));
    }

    /**
     * Rows of `[value, length, whether it can be a code]`.
     *
     * @return iterable<string, array{0: string, 1: int, 2: bool}>
     */
    public static function provideCodeShapes(): iterable
    {
        yield from [
            'six digits'        => ['012345', 6, true],
            'ten digits'        => ['0123456789', 10, true],
            'one digit short'   => ['12345', 6, false],
            'one digit over'    => ['1234567', 6, false],
            'a letter'          => ['12345a', 6, false],
            'surrounding space' => [' 123456', 6, false],
            'trailing newline'  => ["123456\n", 6, false],
            'full-width digits' => ['１２３４５６', 6, false],
            'a signed number'   => ['+12345', 6, false],
        ];
    }

    /**
     * A code is a string of exactly the configured number of ASCII digits.
     *
     * @param  string  $value
     * @param  int  $length
     * @param  bool  $wellFormed
     * @return void
     */
    #[DataProvider('provideCodeShapes')]
    public function testTellsWhetherAValueCanBeACode(string $value, int $length, bool $wellFormed): void
    {
        config()->set('authentication.codes.length', $length);

        self::assertSame($wellFormed, self::codes()->isWellFormed($value));
    }

    /**
     * The container builds the engine with the secure generator.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheContainerBuildsTheEngineWithTheSecureGenerator(): void
    {
        $issued = app(OneTimeCodes::class)->issue(self::binding(), $this->now);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertSame(self::codeHash(self::binding(), $issued->issueId, $issued->code()), DB::table('one_time_codes')->value('code_hash'));
    }

    /**
     * Counts on the code's row are part of whatever transaction the caller
     * holds open on its connection: rolling it back gives the attempt back.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACallersRollbackGivesTheAttemptBack(): void
    {
        $binding = self::binding();
        $wrong   = self::issued($binding)->code() === '000000' ? '111111' : '000000';

        DB::beginTransaction();

        self::assertSame(CodeCheck::WRONG, self::codes()->check($binding, self::challenge(), $wrong, $this->now));
        self::assertSame(1, self::attempts());

        DB::rollBack();

        self::assertSame(0, self::attempts());
    }

    /**
     * A token is 32 random bytes, base64url without padding, issued for the
     * lifetime given and stored only as its keyed hash, under the binding's
     * digest, with the purpose and guard; no two are alike.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenIsStoredOnlyAsItsKeyedHash(): void
    {
        $binding = self::linkBinding();
        $issued  = self::codes()->issueToken($binding, $this->now, 900);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/D', $issued->code());
        self::assertSame(32, strlen((string) base64_decode(strtr($issued->code(), '-_', '+/'), true)));
        self::assertTrue($this->now->addSeconds(900)->equalTo($issued->expiresAt));

        $row = (array) DB::table('one_time_codes')->sole();

        self::assertSame([self::bindingDigest($binding), 'password_reset_link', 'mobile'], [$row['id'], $row['purpose'], $row['guard']]);
        self::assertSame(self::codeHash($binding, $issued->issueId, $issued->code()), $row['code_hash']);
        self::assertSame(['2026-04-06 12:00:00', '2026-04-06 12:15:00'], [$row['issued_at'], $row['expires_at']]);

        foreach ($row as $value) {
            self::assertNotSame($issued->code(), $value);
        }

        $tokens = [];

        foreach (range(1, 20) as $offset) {

            $other = self::codes()->issueToken(CodeBinding::passwordResetLink('mobile', 'email', "user{$offset}@example.test"), $this->now, 900);

            self::assertInstanceOf(IssuedCode::class, $other);

            $tokens[] = $other->code();
        }

        self::assertCount(20, array_unique($tokens));
    }

    /**
     * The right token is accepted once; a wrong one is invalid and counts no
     * attempt, however many are tried; a used one stays invalid.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenIsAcceptedOnceAndNeverCountsAttempts(): void
    {
        $binding = self::linkBinding();
        $issued  = self::codes()->issueToken($binding, $this->now, 900);

        self::assertInstanceOf(IssuedCode::class, $issued);

        foreach (range(1, 10) as $ignored) {
            self::assertSame(CodeCheck::INVALID, self::codes()->checkToken($binding, str_repeat('A', 43), $this->now));
        }

        self::assertSame(0, self::attempts());
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->checkToken($binding, $issued->code(), $this->now));
        self::assertSame(CodeCheck::INVALID, self::codes()->checkToken($binding, $issued->code(), $this->now));
        self::assertSame(CodeCheck::INVALID, self::codes()->checkToken($binding, $issued->code(), $this->now->addSeconds(900)));
        self::assertSame('2026-04-06 12:00:00', DB::table('one_time_codes')->value('consumed_at'));
    }

    /**
     * A matching token is expired from the second its lifetime ends; a wrong
     * one is invalid even then, and a binding with no token is invalid.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOnlyTheRightTokenIsReportedExpired(): void
    {
        $binding = self::linkBinding();
        $issued  = self::codes()->issueToken($binding, $this->now, 900);

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertSame(CodeCheck::EXPIRED, self::codes()->checkToken($binding, $issued->code(), $this->now->addSeconds(900)));
        self::assertSame(CodeCheck::INVALID, self::codes()->checkToken($binding, str_repeat('A', 43), $this->now->addSeconds(900)));
        self::assertSame(CodeCheck::INVALID, self::codes()->checkToken(CodeBinding::passwordResetLink('web', 'email', 'ada@example.test'), $issued->code(), $this->now));
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->checkToken($binding, $issued->code(), $this->now->addSeconds(899)));
    }

    /**
     * A token checks only against its own binding: not as a reset code for the
     * same identifier, nor for another guard or identifier.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenWorksOnlyForItsBinding(): void
    {
        $binding = self::linkBinding();
        $issued  = self::codes()->issueToken($binding, $this->now, 900);

        self::assertInstanceOf(IssuedCode::class, $issued);

        $others = [
            CodeBinding::passwordReset('mobile', 'email', 'ada@example.test'),
            CodeBinding::passwordResetLink('web', 'email', 'ada@example.test'),
            CodeBinding::passwordResetLink('mobile', 'email', 'grace@example.test'),
        ];

        foreach ($others as $other) {
            self::assertSame(CodeCheck::INVALID, self::codes()->checkToken($other, $issued->code(), $this->now));
        }

        self::assertSame(CodeCheck::ACCEPTED, self::codes()->checkToken($binding, $issued->code(), $this->now));
    }

    /**
     * Of two checks of one token, the one that uses it up first is accepted;
     * the other, which read it live, is invalid.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOnlyTheCheckThatUsesTheTokenUpIsAccepted(): void
    {
        $binding = self::linkBinding();
        $issued  = self::codes()->issueToken($binding, $this->now, 900);
        $codes   = self::codes();
        $other   = null;

        self::assertInstanceOf(IssuedCode::class, $issued);

        $this->afterTheCheckReads(static function () use ($codes, $binding, $issued, &$other): void {
            $other = $codes->checkToken($binding, $issued->code(), CarbonImmutable::now());
        });

        self::assertSame(CodeCheck::INVALID, $codes->checkToken($binding, $issued->code(), $this->now));
        self::assertSame(CodeCheck::ACCEPTED, $other);
    }

    /**
     * Rows of `[value, whether it can be a token]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideTokenShapes(): iterable
    {
        yield from [
            '43 base64url characters' => [str_repeat('aZ09-_', 7) . 'a', true],
            'one short'               => [str_repeat('a', 42), false],
            'one over'                => [str_repeat('a', 44), false],
            'padded'                  => [str_repeat('a', 42) . '=', false],
            'standard base64'         => [str_repeat('a', 42) . '+', false],
            'a trailing newline'      => [str_repeat('a', 43) . "\n", false],
            'a code'                  => ['123456', false],
        ];
    }

    /**
     * A token is exactly 43 base64url characters.
     *
     * @param  string  $value
     * @param  bool  $wellFormed
     * @return void
     */
    #[DataProvider('provideTokenShapes')]
    public function testTellsWhetherAValueCanBeAToken(string $value, bool $wellFormed): void
    {
        self::assertSame($wellFormed, self::codes()->isWellFormedToken($value));
    }

    /**
     * Invalidating ends exactly the listed bindings' unused challenges, in one
     * statement (none for an empty list, a binding listed twice or one with no
     * row): each is used up now under a new issuance, so none can be checked
     * again, while its row keeps its window, deliveries, last delivery and
     * expiry. A binding not listed is left as it is, and invalidating an ended
     * challenge again ends nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testInvalidatingEndsExactlyTheListedBindings(): void
    {
        $ada    = new PlainIdentityFixture(1);
        $signIn = self::binding();
        $reset  = CodeBinding::passwordReset('mobile', 'phone', self::PHONE);
        $link   = CodeBinding::passwordResetLink('mobile', 'phone', self::PHONE);
        $change = CodeBinding::identifierChange('mobile', 'phone', self::PHONE, $ada, 'request-1');
        $kept   = CodeBinding::verification('mobile', 'phone', self::PHONE, $ada);

        foreach ([$signIn, $reset, $link, $change, $kept] as $binding) {
            self::issued($binding);
        }

        self::codes()->check($signIn, self::challenge($signIn), '000000', $this->now);

        $before = self::rows();

        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append($query->sql);
        });

        self::assertSame(0, self::codes()->invalidate([]));
        self::assertCount(0, $statements);

        CarbonImmutable::setTestNow($this->now->addSeconds(30));

        $ended = self::codes()->invalidate([$signIn, $reset, $link, $change, $reset, CodeBinding::signIn('web', 'phone', self::PHONE)]);

        self::assertSame(4, $ended);
        self::assertCount(1, $statements);
        self::assertStringStartsWith('update', strtolower($statements[0]));

        $after = self::rows();

        self::assertSame(array_keys($before), array_keys($after));

        foreach ($after as $id => $row) {

            $endedNow = $id !== self::bindingDigest($kept);

            self::assertSame($endedNow ? '2026-04-06 12:00:30' : null, $row['consumed_at']);
            self::assertSame($endedNow, $row['issue_id'] !== $before[$id]['issue_id']);

            foreach (['challenge_id', 'code_hash', 'attempts', 'deliveries', 'window_started_at', 'issued_at', 'expires_at'] as $column) {
                self::assertSame($before[$id][$column], $row[$column], $column);
            }
        }

        self::assertSame(CodeCheck::INVALID, self::codes()->check($reset, self::challenge($reset), '000000', $this->now));
        self::assertSame(0, self::codes()->invalidate([$signIn, $reset]));
    }

    /**
     * Ending a key's challenge resets neither its delivery cap nor its resend
     * cooldown: a delivery straight after waits out the cooldown since the last
     * one, the next is refused while the window has had all its deliveries, and
     * one is made again only once the window ends.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnEndedChallengeKeepsItsKeysCooldownAndDeliveryCap(): void
    {
        $binding = self::binding();

        foreach ([0, 60, 120] as $second) {
            self::assertInstanceOf(IssuedCode::class, self::codes()->issue($binding, $this->now->addSeconds($second)));
        }

        self::codes()->invalidate([$binding]);

        $soon = self::codes()->issue($binding, $this->now->addSeconds(130));
        $late = self::codes()->issue($binding, $this->now->addSeconds(180));

        self::assertInstanceOf(DeliveryRefusal::class, $soon);
        self::assertSame([50, false], [$soon->retryAfter, $soon->exhausted]);
        self::assertInstanceOf(DeliveryRefusal::class, $late);
        self::assertSame([1620, true], [$late->retryAfter, $late->exhausted]);
        self::assertSame(3, self::deliveries());
        self::assertInstanceOf(IssuedCode::class, self::codes()->issue($binding, $this->now->addSeconds(1800)));
    }

    /**
     * A check that names another challenge than the live one, a well-formed id
     * or a stale one, is invalid and spends no attempt, even with the right
     * code; the live challenge still accepts it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACheckForAnotherChallengeSpendsNothing(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        $binding = self::binding();
        $first   = self::issued($binding);

        self::codes()->invalidate([$binding]);

        $issued = self::issued($binding);

        foreach ([self::NO_CHALLENGE, $first->challengeId] as $other) {
            self::assertSame(CodeCheck::INVALID, self::codes()->check($binding, $other, $issued->code(), $this->now));
        }

        self::assertSame(0, self::attempts());
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check($binding, $issued->challengeId, $issued->code(), $this->now));
    }

    /**
     * Rows of `[value, whether it can be a challenge id]`.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideChallengeShapes(): iterable
    {
        yield from [
            'an issued id'      => ['0195f4a2-7b1c-4000-8000-00000000000a', true],
            'upper case'        => ['0195F4A2-7B1C-4000-8000-00000000000A', false],
            'no hyphens'        => ['0195f4a27b1c4000800000000000000a', false],
            'a trailing break'  => ["0195f4a2-7b1c-4000-8000-00000000000a\n", false],
            'one character off' => ['0195f4a2-7b1c-4000-8000-00000000000', false],
            'empty'             => ['', false],
        ];
    }

    /**
     * Only a lower-case UUID can be a challenge id the engine issued.
     *
     * @param  string  $value
     * @param  bool  $wellFormed
     * @return void
     */
    #[DataProvider('provideChallengeShapes')]
    public function testTellsWhetherAValueCanBeAChallenge(string $value, bool $wellFormed): void
    {
        self::assertSame($wellFormed, self::codes()->isWellFormedChallenge($value));
    }

    /**
     * The attempts counted against the live code.
     *
     * @return int
     */
    private static function attempts(): int
    {
        $attempts = DB::table('one_time_codes')->value('attempts');

        self::assertIsNumeric($attempts);

        return (int) $attempts;
    }

    /**
     * The deliveries counted in the live code's delivery window.
     *
     * @return int
     */
    private static function deliveries(): int
    {
        $deliveries = DB::table('one_time_codes')->value('deliveries');

        self::assertIsNumeric($deliveries);

        return (int) $deliveries;
    }

    /**
     * Every row of the table as stored, by key.
     *
     * @return array<string, array<string, mixed>>
     */
    private static function rows(): array
    {
        $rows = [];

        foreach (DB::table('one_time_codes')->orderBy('id')->get() as $row) {
            $rows[(string) $row->id] = (array) $row;
        }

        return $rows;
    }

    /**
     * The binding the codes are issued for.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeBinding
     */
    private static function binding(): CodeBinding
    {
        return CodeBinding::signIn('mobile', 'phone', self::PHONE);
    }

    /**
     * The binding the reset link tokens are issued for.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\CodeBinding
     */
    private static function linkBinding(): CodeBinding
    {
        return CodeBinding::passwordResetLink('mobile', 'email', 'ada@example.test');
    }

    /**
     * Issue a code for the binding now, the given one when given.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  ?string  $code
     * @return \SineMacula\Laravel\Authentication\Codes\IssuedCode
     *
     * @throws \Random\RandomException
     */
    private function issued(CodeBinding $binding, ?string $code = null): IssuedCode
    {
        $issued = ($code === null ? self::codes() : self::sequence([$code]))->issue($binding, $this->now);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued;
    }

    /**
     * The engine as the container builds it.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\OneTimeCodes
     */
    private static function codes(): OneTimeCodes
    {
        return app(OneTimeCodes::class);
    }

    /**
     * Run the change once, right after the next check reads the code and before
     * it counts its attempt, as a concurrent request would.
     *
     * @param  \Closure(): void  $change
     * @return void
     */
    private function afterTheCheckReads(\Closure $change): void
    {
        $this->onceAfter(static fn (string $sql): bool => str_starts_with($sql, 'select') && str_contains($sql, 'one_time_codes'), $change);
    }

    /**
     * Run the change once, right after the next check counts its attempt and
     * before it uses the code up.
     *
     * @param  \Closure(): void  $change
     * @return void
     */
    private function afterTheAttemptIsCounted(\Closure $change): void
    {
        $this->onceAfter(static fn (string $sql): bool => str_starts_with($sql, 'update') && str_contains($sql, 'attempts'), $change);
    }

    /**
     * Run the change once, right after the first statement the predicate
     * matches.
     *
     * @param  \Closure(string): bool  $matches
     * @param  \Closure(): void  $change
     * @return void
     */
    private function onceAfter(\Closure $matches, \Closure $change): void
    {
        $done = false;

        DB::listen(static function (QueryExecuted $query) use ($matches, $change, &$done): void {
            if ($done || !$matches(strtolower($query->sql))) {
                return;
            }

            $done = true;

            $change();
        });
    }
}
