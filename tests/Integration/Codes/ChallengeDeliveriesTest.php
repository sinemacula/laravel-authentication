<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\ChallengeDeliveries;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeDelivery;
use SineMacula\Laravel\Authentication\Codes\DeliveryRefusal;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeCheck;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use Tests\Concerns\InteractsWithCodes;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Integration tests for how the one-time code engine writes a delivery to its
 * key's row, against the shipped table: the resend cooldown, a resend of the
 * live challenge (its id and attempts kept, its code replaced), a new challenge
 * for another transaction or once the last ended, the delivery window, its cap
 * and the lifetime it bounds, a reset link's token, and what a delivery does
 * when another request changes the row between its read and its write.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ChallengeDeliveries::class)]
#[CoversClass(CodeDelivery::class)]
final class ChallengeDeliveriesTest extends TestCase
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
     * Within the resend cooldown no new code is issued: the answer is the
     * seconds until one may be, at least 1, and the live code is untouched.
     * From the second the cooldown ends, a new code replaces it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheResendCooldownHoldsBackANewCode(): void
    {
        $binding = self::binding();
        $first   = self::codes()->issue($binding, $this->now);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertSame(60, self::cooldownOf(self::codes()->issue($binding, $this->now)));
        self::assertSame(1, self::cooldownOf(self::codes()->issue($binding, $this->now->addSeconds(59))));
        self::assertSame($first->issueId, DB::table('one_time_codes')->value('issue_id'));

        $second = self::codes()->issue($binding, $this->now->addSeconds(60));

        self::assertInstanceOf(IssuedCode::class, $second);
        self::assertNotSame($first->issueId, $second->issueId);
        self::assertSame(1, DB::table('one_time_codes')->count());
    }

    /**
     * A resend replaces the previous code at once, in the one update after its
     * read: the old code no longer works, the new one does, and the challenge
     * keeps its id and the attempts already spent on it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendInvalidatesThePreviousCode(): void
    {
        $binding    = self::binding();
        $codes      = self::sequence(['111111', '222222']);
        $later      = $this->now->addSeconds(60);
        $statements = [];

        $first = $codes->issue($binding, $this->now);

        self::assertSame(CodeCheck::WRONG, $codes->check($binding, self::challenge(), '999999', $this->now));

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = (string) strtok(strtolower($query->sql), ' ');
        });

        $second = $codes->issue($binding, $later);

        self::assertSame(['select', 'update'], $statements);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $second);
        self::assertSame($first->challengeId, $second->challengeId);
        self::assertNotSame($first->issueId, $second->issueId);
        self::assertSame(1, self::attempts());
        self::assertSame(CodeCheck::WRONG, $codes->check($binding, self::challenge(), '111111', $later));
        self::assertSame(CodeCheck::ACCEPTED, $codes->check($binding, self::challenge(), '222222', $later));
    }

    /**
     * `issueFirst()` writes only the insert for a binding with no code, and,
     * for one that has a code, falls back to `issue()`'s rules once its insert
     * is refused: it reads the row, and within the cooldown answers the wait,
     * after it replaces the code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFirstIssueInsertsBeforeItWouldReplace(): void
    {
        $binding    = self::binding();
        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = (string) strtok(strtolower($query->sql), ' ');
        });

        $recorded = static function () use (&$statements): array {
            $taken      = $statements;
            $statements = [];

            return $taken;
        };

        $first = self::codes()->issueFirst($binding, $this->now);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertSame(['insert'], $recorded());

        self::assertSame(30, self::cooldownOf(self::codes()->issueFirst($binding, $this->now->addSeconds(30))));
        self::assertSame(['insert', 'select'], $recorded());

        $replacement = self::codes()->issueFirst($binding, $this->now->addSeconds(60));

        self::assertInstanceOf(IssuedCode::class, $replacement);
        self::assertSame($replacement->issueId, DB::table('one_time_codes')->value('issue_id'));
        self::assertSame(1, DB::table('one_time_codes')->count());
    }

    /**
     * A code pruned between an issue's refused insert and its read leaves a
     * wait of one second, as does an issue that a concurrent one beat to the
     * replacement when there is no cooldown at all.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIssueThatLosesItsCodeMeanwhileWaitsOneSecond(): void
    {
        $binding    = self::binding();
        $concurrent = self::sequence(['222222']);

        $this->onceAfter(static fn (string $sql): bool => str_starts_with($sql, 'select'), function () use ($concurrent, $binding): void {
            $concurrent->issue($binding, CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

            $this->onceAfter(static fn (string $sql): bool => str_starts_with($sql, 'insert'), static function (): void {
                DB::table('one_time_codes')->delete();
            });
        });

        self::assertSame(1, self::cooldownOf(self::codes()->issue($binding, $this->now->addSeconds(30))));

        self::codes()->issue($binding, $this->now);

        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        $concurrent = self::sequence(['111111']);

        $this->onceAfter(static fn (string $sql): bool => str_starts_with($sql, 'select'), static function () use ($concurrent, $binding): void {
            $concurrent->issue($binding, CarbonImmutable::createStrict(2026, 4, 6, 12, 5, 0));
        });

        self::assertSame(1, self::cooldownOf(self::codes()->issue($binding, $this->now->addSeconds(300))));
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check($binding, self::challenge(), '111111', $this->now->addSeconds(300)));
    }

    /**
     * An issue that a concurrent one beat to the replacement waits out the
     * cooldown from the delivery that won, not from the one it read.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnIssueBeatenToTheReplacementWaitsOutTheWinnersCooldown(): void
    {
        $binding    = self::binding();
        $concurrent = self::sequence(['222222']);
        $later      = $this->now->addSeconds(90);

        self::codes()->issue($binding, $this->now);

        $this->onceAfter(static fn (string $sql): bool => str_starts_with($sql, 'select'), static function () use ($concurrent, $binding, $later): void {
            $concurrent->issue($binding, $later->subSeconds(20));
        });

        self::assertSame(40, self::cooldownOf(self::codes()->issue($binding, $later)));
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->check($binding, self::challenge(), '222222', $later));
    }

    /**
     * With no cooldown every request issues a new code.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoCooldownIssuesEveryTime(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        $first  = self::codes()->issue(self::binding(), $this->now);
        $second = self::codes()->issue(self::binding(), $this->now);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $second);
        self::assertSame($second->issueId, DB::table('one_time_codes')->value('issue_id'));
    }

    /**
     * A token shares the codes' resend cooldown: within it no new token is
     * issued and the seconds left are answered; from its end a new token
     * replaces the old one, which stops working.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenFollowsTheResendCooldown(): void
    {
        $binding = self::linkBinding();
        $first   = self::codes()->issueToken($binding, $this->now, 900);

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertSame(1, self::cooldownOf(self::codes()->issueToken($binding, $this->now->addSeconds(59), 900)));

        $second = self::codes()->issueToken($binding, $this->now->addSeconds(60), 900);

        self::assertInstanceOf(IssuedCode::class, $second);
        self::assertSame(CodeCheck::INVALID, self::codes()->checkToken($binding, $first->code(), $this->now->addSeconds(60)));
        self::assertSame(CodeCheck::ACCEPTED, self::codes()->checkToken($binding, $second->code(), $this->now->addSeconds(60)));
    }

    /**
     * Every delivery to a key counts in its window, a first one included,
     * whatever the challenge: once the window has had `max_deliveries`, a
     * further request is refused until the window ends, with the wait.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheDeliveriesOfAWindowAreCapped(): void
    {
        config()->set('authentication.codes.max_deliveries', 3);

        $binding = self::binding();
        $codes   = self::codes();

        foreach ([0, 60, 120] as $delivery => $second) {
            self::assertInstanceOf(IssuedCode::class, $codes->issue($binding, $this->now->addSeconds($second)));
            self::assertSame($delivery + 1, self::column('deliveries'));
        }

        $refused = $codes->issue($binding, $this->now->addSeconds(180));

        self::assertInstanceOf(DeliveryRefusal::class, $refused);
        self::assertSame([true, 1620], [$refused->exhausted, $refused->retryAfter]);
        self::assertSame(3, self::column('deliveries'));

        $last = $codes->issue($binding, $this->now->addSeconds(1799));

        self::assertInstanceOf(DeliveryRefusal::class, $last);
        self::assertSame([true, 1], [$last->exhausted, $last->retryAfter]);
    }

    /**
     * A window that has ended starts afresh at the next request: its first
     * delivery, a new challenge with no attempts, the window starting now.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testANewWindowStartsOnceTheLastEnds(): void
    {
        config()->set('authentication.codes.max_deliveries', 1);

        $binding = self::binding();
        $codes   = self::codes();
        $first   = $codes->issue($binding, $this->now);

        $codes->check($binding, self::challenge(), '000000', $this->now);

        self::assertInstanceOf(DeliveryRefusal::class, $codes->issue($binding, $this->now->addSeconds(1799)));

        $next = $codes->issue($binding, $this->now->addSeconds(1800));
        $row  = (array) DB::table('one_time_codes')->sole();

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $next);
        self::assertNotSame($first->challengeId, $next->challengeId);
        self::assertSame(
            [1, 0, '2026-04-06 12:30:00', '2026-04-06 12:40:00'],
            [self::column('deliveries'), self::column('attempts'), $row['window_started_at'], $row['expires_at']],
        );
        self::assertTrue($this->now->addSeconds(2400)->equalTo($next->expiresAt));
    }

    /**
     * A resend keeps the challenge but never extends it past its window: its
     * code expires at the earlier of its own lifetime and the window's end.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendNeverOutlivesTheWindow(): void
    {
        config()->set('authentication.codes.delivery_window_seconds', 900);

        $binding = self::binding();
        $first   = self::codes()->issue($binding, $this->now);
        $resent  = self::codes()->issue($binding, $this->now->addSeconds(400));

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $resent);
        self::assertSame($first->challengeId, $resent->challengeId);
        self::assertTrue($this->now->addSeconds(900)->equalTo($resent->expiresAt));
        self::assertSame('2026-04-06 12:15:00', DB::table('one_time_codes')->value('expires_at'));
        self::assertSame(CodeCheck::EXPIRED, self::codes()->check($binding, $resent->challengeId, $resent->code(), $this->now->addSeconds(900)));
    }

    /**
     * A code the window would leave less than the resend cooldown to live is
     * not delivered: the request waits for the window to end, counting nothing,
     * since the code could expire before another may be asked for. With the
     * cooldown exactly left, the code is delivered and lives to the window's
     * end; a reset link's token, which the window never cuts short, is
     * delivered whatever is left of it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACodeTheWindowWouldCutShorterThanTheCooldownWaitsForItToEnd(): void
    {
        $binding = self::binding();
        $codes   = self::codes();

        self::assertInstanceOf(IssuedCode::class, $codes->issue($binding, $this->now));

        $refused = $codes->issue($binding, $this->now->addSeconds(1741));

        self::assertInstanceOf(DeliveryRefusal::class, $refused);
        self::assertSame([false, 59], [$refused->exhausted, $refused->retryAfter]);
        self::assertSame(1, self::column('deliveries'));

        $last = $codes->issue($binding, $this->now->addSeconds(1740));

        self::assertInstanceOf(IssuedCode::class, $last);
        self::assertTrue($this->now->addSeconds(1800)->equalTo($last->expiresAt));
        self::assertSame(2, self::column('deliveries'));

        DB::table('one_time_codes')->delete();

        $link = self::linkBinding();

        self::assertInstanceOf(IssuedCode::class, $codes->issueToken($link, $this->now, 3600));

        $token = $codes->issueToken($link, $this->now->addSeconds(1790), 3600);

        self::assertInstanceOf(IssuedCode::class, $token);
        self::assertTrue($this->now->addSeconds(5390)->equalTo($token->expiresAt));
    }

    /**
     * Rows of `[what ended the live challenge, the second the next request is
     * made at]`: a challenge that expired, used up its attempts or was used is
     * replaced by a new one in the same window, which keeps its deliveries.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: int}>
     */
    public static function provideEndedChallenges(): iterable
    {
        yield from [
            'expired'   => [[], 600],
            'exhausted' => [['attempts' => 5], 60],
            'used'      => [['consumed_at' => '2026-04-06 12:00:30'], 60],
        ];
    }

    /**
     * A request after the live challenge ended starts a new challenge in the
     * same window: a new id, no attempts, unused, and one more delivery, never
     * a fresh delivery budget.
     *
     * @param  array<string, mixed>  $ending
     * @param  int  $second
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideEndedChallenges')]
    public function testAnEndedChallengeIsReplacedInTheSameWindow(array $ending, int $second): void
    {
        $binding = self::binding();
        $first   = self::codes()->issue($binding, $this->now);

        if ($ending !== []) {
            DB::table('one_time_codes')->update($ending);
        }

        $next = self::codes()->issue($binding, $this->now->addSeconds($second));
        $row  = (array) DB::table('one_time_codes')->sole();

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $next);
        self::assertNotSame($first->challengeId, $next->challengeId);
        self::assertSame(
            [$next->challengeId, 2, 0, null, '2026-04-06 12:00:00'],
            [$row['challenge_id'], self::column('deliveries'), self::column('attempts'), $row['consumed_at'], $row['window_started_at']],
        );
    }

    /**
     * A resend whose challenge another request ends between its read and its
     * write (a check that used it) is written as a new challenge instead, so a
     * used challenge never comes back to life.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAResendOvertakenByAUseStartsANewChallenge(): void
    {
        $binding = self::binding();
        $first   = self::codes()->issue($binding, $this->now);

        $this->onceAfter(static fn (string $sql): bool => str_starts_with($sql, 'select'), static function (): void {
            DB::table('one_time_codes')->update(['consumed_at' => '2026-04-06 12:00:59']);
        });

        $next = self::codes()->issue($binding, $this->now->addSeconds(60));

        self::assertInstanceOf(IssuedCode::class, $first);
        self::assertInstanceOf(IssuedCode::class, $next);
        self::assertNotSame($first->challengeId, $next->challengeId);
        self::assertSame(
            [$next->challengeId, null, 2],
            [DB::table('one_time_codes')->value('challenge_id'), DB::table('one_time_codes')->value('consumed_at'), self::column('deliveries')],
        );
    }

    /**
     * A further factor's challenges are bound to their transaction: a request
     * for another session or factor on the same destination starts a new
     * challenge in the same window, under the same cooldown and cap, and a code
     * is accepted only for the transaction it was sent for; a check for another
     * transaction, even naming the live challenge, spends nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAFactorChallengeIsBoundToItsTransaction(): void
    {
        $ada    = new PlainIdentityFixture(1);
        $first  = CodeBinding::factor('mobile', self::factor($ada, 'session-1'));
        $second = CodeBinding::factor('mobile', self::factor($ada, 'session-2'));
        $codes  = self::sequence(['111111', '000000', '222222']);
        $issued = $codes->issue($first, $this->now);

        self::assertSame(30, self::cooldownOf($codes->issue($second, $this->now->addSeconds(30))));

        $other = $codes->issue($second, $this->now->addSeconds(60));

        self::assertInstanceOf(IssuedCode::class, $issued);
        self::assertInstanceOf(IssuedCode::class, $other);
        self::assertNotSame($issued->challengeId, $other->challengeId);
        self::assertSame([1, 2], [DB::table('one_time_codes')->count(), self::column('deliveries')]);
        self::assertSame(CodeCheck::INVALID, $codes->check($first, $other->challengeId, '222222', $this->now->addSeconds(60)));
        self::assertSame(CodeCheck::INVALID, $codes->check($second, $issued->challengeId, '111111', $this->now->addSeconds(60)));
        self::assertSame(0, self::attempts());
        self::assertSame(CodeCheck::ACCEPTED, $codes->check($second, $other->challengeId, '222222', $this->now->addSeconds(60)));
    }

    /**
     * A reset link's token works for the lifetime its caller gives, even past
     * the delivery window, while it still counts against the window's cap.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATokenIsNotCutShortByTheWindow(): void
    {
        config()->set('authentication.codes.max_deliveries', 2);

        $binding = self::linkBinding();

        self::codes()->issueToken($binding, $this->now, 3600);

        $resent = self::codes()->issueToken($binding, $this->now->addSeconds(60), 3600);

        self::assertInstanceOf(IssuedCode::class, $resent);
        self::assertTrue($this->now->addSeconds(3660)->equalTo($resent->expiresAt));
        self::assertInstanceOf(DeliveryRefusal::class, self::codes()->issueToken($binding, $this->now->addSeconds(120), 3600));
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
     * The column of the one code row, as an integer.
     *
     * @param  string  $column
     * @return int
     *
     * @phpstan-impure
     */
    private static function column(string $column): int
    {
        $value = DB::table('one_time_codes')->value($column);

        self::assertIsNumeric($value);

        return (int) $value;
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
     * A further factor's code binding for the identity's text message factor,
     * for the session given, on a sign-in.
     *
     * @param  \Tests\Unit\Stubs\PlainIdentityFixture  $identity
     * @param  string  $session
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding
     */
    private static function factor(PlainIdentityFixture $identity, string $session): FactorCodeBinding
    {
        return new FactorCodeBinding(new ProofBinding($identity, 'mobile', $session, Purpose::SIGN_IN), 'factor-1', new Channel(ChannelKind::SMS, self::PHONE));
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
     * The engine as the container builds it.
     *
     * @return \SineMacula\Laravel\Authentication\Codes\OneTimeCodes
     */
    private static function codes(): OneTimeCodes
    {
        return app(OneTimeCodes::class);
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
