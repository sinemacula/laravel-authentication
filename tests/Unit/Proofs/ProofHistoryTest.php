<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\ProofHistory;

/**
 * Unit tests for what a session's summary rows say about its authentication:
 * the newest time of any kind as `auth_time`; the first factor's, further
 * factors' and recovery codes' values as `amr`, once each, in a fixed order, a
 * stored `mfa` dropped and `mfa` added only from a reported multifactor
 * evaluation; and nothing from a reauthentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofHistory::class)]
final class ProofHistoryTest extends TestCase
{
    /**
     * With no rows there is no authentication time, no first factor and no
     * value.
     *
     * @return void
     */
    public function testNoRowsSayNothing(): void
    {
        $history = new ProofHistory([]);

        self::assertNull($history->authenticatedAt());
        self::assertFalse($history->hasFirstFactor());
        self::assertSame([], $history->methods());
    }

    /**
     * The authentication time is the newest of every kind's, a
     * reauthentication's and a step-up's included, whatever order the rows come
     * in.
     *
     * @return void
     */
    public function testTheAuthenticationTimeIsTheNewestOfAnyKind(): void
    {
        $history = new ProofHistory([
            self::row(ProofKind::ADDITIONAL_FACTOR, ['otp'], false, '2026-04-06 12:05:00'),
            self::row(ProofKind::FIRST_FACTOR, ['pwd'], false, '2026-04-06 12:00:00'),
            self::row(ProofKind::EXTERNAL_REAUTHENTICATION, [], false, '2026-04-06 12:30:00'),
            self::row(ProofKind::FIRST_FACTOR_REAUTHENTICATION, ['pwd'], false, '2026-04-06 12:10:00'),
        ]);

        self::assertSame('2026-04-06 12:30:00', $history->authenticatedAt()?->format('Y-m-d H:i:s'));
        self::assertTrue($history->hasFirstFactor());
        self::assertFalse((new ProofHistory([self::row(ProofKind::ADDITIONAL_FACTOR, ['otp'], true, '2026-04-06 12:00:00')]))->hasFirstFactor());
    }

    /**
     * The values are the first factor's, the further factors' and the recovery
     * codes', once each, in the order of their rows' times and then of their
     * values, whatever order the rows come in; a reauthentication adds none.
     *
     * @return void
     */
    public function testTheMethodsAreTheFactorsValuesInAFixedOrder(): void
    {
        $rows = [
            self::row(ProofKind::RECOVERY_CODE, ['kba', 'otp'], false, '2026-04-06 12:05:00'),
            self::row(ProofKind::FIRST_FACTOR_REAUTHENTICATION, ['pop'], false, '2026-04-06 12:20:00'),
            self::row(ProofKind::ADDITIONAL_FACTOR, ['sms'], false, '2026-04-06 12:05:00'),
            self::row(ProofKind::FIRST_FACTOR, ['pwd'], false, '2026-04-06 12:00:00'),
            self::row(ProofKind::EXTERNAL_REAUTHENTICATION, ['hwk'], false, '2026-04-06 12:30:00'),
            self::row(ProofKind::ADDITIONAL_FACTOR, ['otp', 'pwd'], false, '2026-04-06 12:10:00'),
        ];

        self::assertSame(['pwd', 'kba', 'otp', 'sms'], (new ProofHistory($rows))->methods());
        self::assertSame(['pwd', 'kba', 'otp', 'sms'], (new ProofHistory(array_reverse($rows)))->methods());
    }

    /**
     * `mfa` is added only when a further factor's or a recovery code's
     * evaluation reported multifactor authentication, after the other values;
     * a stored `mfa` is dropped, and a first factor or a reauthentication that
     * claims multifactor adds nothing.
     *
     * @return void
     */
    public function testMfaComesOnlyFromAReportedMultifactorEvaluation(): void
    {
        $first = self::row(ProofKind::FIRST_FACTOR, ['pwd', 'mfa'], true, '2026-04-06 12:00:00');

        self::assertSame(['pwd'], (new ProofHistory([$first, self::row(ProofKind::FIRST_FACTOR_REAUTHENTICATION, ['pwd'], true, '2026-04-06 12:01:00')]))->methods());
        self::assertSame(['pwd', 'otp'], (new ProofHistory([$first, self::row(ProofKind::ADDITIONAL_FACTOR, ['otp'], false, '2026-04-06 12:01:00')]))->methods());
        self::assertSame(['pwd', 'otp', 'mfa'], (new ProofHistory([$first, self::row(ProofKind::ADDITIONAL_FACTOR, ['otp'], true, '2026-04-06 12:01:00')]))->methods());
        self::assertSame(['pwd', 'mfa'], (new ProofHistory([$first, self::row(ProofKind::RECOVERY_CODE, [], true, '2026-04-06 12:01:00')]))->methods());
    }

    /**
     * One summary row.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  list<string>  $methods
     * @param  bool  $multifactor
     * @param  string  $at
     * @return array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, at: \Carbon\CarbonImmutable}
     */
    private static function row(ProofKind $kind, array $methods, bool $multifactor, string $at): array
    {
        return ['kind' => $kind, 'methods' => $methods, 'multifactor' => $multifactor, 'at' => CarbonImmutable::parse($at)];
    }
}
