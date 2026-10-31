<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\TestCase;

/**
 * Proves each outcome of checking a verification code is what the check wrote,
 * on whichever engine the suite runs against: the identifier recorded verified
 * only for `verified`, the code used up by every accepted check, and an attempt
 * counted only against a code that was compared and did not match.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeService::class)]
final class CodeVerificationOutcomesTest extends TestCase
{
    use InteractsWithCodeIdentities;

    /** @var string The code the engine issues first. */
    private const string CODE = '135790';

    /** @var string When the seeded identity's identifiers were verified. */
    private const string VERIFIED_BEFORE = '2026-01-01 00:00:00';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clock, create the table and issue known codes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        CarbonImmutable::setTestNow($this->now);

        self::createCodeIdentitiesTable();
        self::issueCodes([self::CODE, '246802']);
    }

    /**
     * Release the clock and drop the table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Rows of `[whether the number starts verified, what happens before the
     * check, code, outcome, number verified at, code used up, attempts]`.
     *
     * @return iterable<string, array{0: bool, 1: string, 2: string, 3: \SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome, 4: ?string, 5: bool, 6: int}>
     */
    public static function provideOutcomes(): iterable
    {
        yield from [
            'verified'         => [false, 'nothing', self::CODE, VerificationOutcome::VERIFIED, '2026-04-06 12:00:00', true, 1],
            'already verified' => [true, 'nothing', self::CODE, VerificationOutcome::ALREADY_VERIFIED, self::VERIFIED_BEFORE, true, 1],
            'mismatch'         => [false, 'change', self::CODE, VerificationOutcome::MISMATCH, null, true, 1],
            'invalid'          => [false, 'nothing', '000000', VerificationOutcome::INVALID, null, false, 1],
            'expired'          => [false, 'expire', self::CODE, VerificationOutcome::EXPIRED, null, false, 0],
            'exhausted'        => [false, 'exhaust', self::CODE, VerificationOutcome::EXHAUSTED, null, false, 1],
        ];
    }

    /**
     * Each outcome leaves the identity's number and the code as it says.
     *
     * @param  bool  $verified
     * @param  string  $before
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\VerificationOutcome  $outcome
     * @param  ?string  $verifiedAt
     * @param  bool  $consumed
     * @param  int  $attempts
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOutcomes')]
    public function testEachOutcomeIsWhatTheCheckWrote(
        bool $verified,
        string $before,
        string $code,
        VerificationOutcome $outcome,
        ?string $verifiedAt,
        bool $consumed,
        int $attempts,
    ): void {
        config()->set('authentication.codes.max_attempts', 1);

        $identity = self::seedCodeIdentity(verified: $verified);

        $this->codeService()->sendVerification($identity, 'phone');

        match ($before) {
            'change'  => DB::table('code_identities')->where('id', $identity->getKey())->update(['phone' => '+447700900124']),
            'expire'  => CarbonImmutable::setTestNow($this->now->addSeconds(600)),
            'exhaust' => $this->codeService()->verify($identity, 'phone', '000000'),
            default   => null,
        };

        self::assertSame($outcome, $this->codeService()->verify($identity, 'phone', $code));

        self::assertSame($verifiedAt, $identity->fresh()?->phone_verified_at?->format('Y-m-d H:i:s'));
        self::assertSame($consumed, DB::table('one_time_codes')->value('consumed_at') !== null);
        self::assertSame($attempts, self::storedAttempts());
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        self::configureCodeGuards(app(ConfigRepository::class));
    }
}
