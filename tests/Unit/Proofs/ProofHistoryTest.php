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
 * stored `mfa` dropped and `mfa` added only from an accepted evaluation that
 * reports multifactor; and nothing from a reauthentication unless it carries an
 * accepted evaluation (an external one whose evidence was accepted).
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
     * `mfa` is added only when an accepted evaluation (a further factor's or a
     * recovery code's) reported multifactor authentication, after the other
     * values; a stored `mfa` is dropped, and a first factor or a
     * reauthentication that claims multifactor with no accepted evaluation adds
     * nothing.
     *
     * @return void
     */
    public function testMfaComesOnlyFromAnAcceptedMultifactorEvaluation(): void
    {
        $first = self::row(ProofKind::FIRST_FACTOR, ['pwd', 'mfa'], true, '2026-04-06 12:00:00');

        self::assertSame(['pwd'], (new ProofHistory([$first, self::row(ProofKind::FIRST_FACTOR_REAUTHENTICATION, ['pwd'], true, '2026-04-06 12:01:00')]))->methods());
        self::assertSame(['pwd', 'otp'], (new ProofHistory([$first, self::row(ProofKind::ADDITIONAL_FACTOR, ['otp'], false, '2026-04-06 12:01:00')]))->methods());
        self::assertSame(['pwd', 'otp', 'mfa'], (new ProofHistory([$first, self::row(ProofKind::ADDITIONAL_FACTOR, ['otp'], true, '2026-04-06 12:01:00')]))->methods());
        self::assertSame(['pwd', 'mfa'], (new ProofHistory([$first, self::row(ProofKind::RECOVERY_CODE, [], true, '2026-04-06 12:01:00')]))->methods());
    }

    /**
     * An external proof counts toward `amr` like any other once its evidence
     * was accepted: a first factor at the provider whose acceptance reports
     * multifactor adds `mfa`, and a reauthentication at the provider with an
     * accepted evaluation adds its values, and `mfa` when it reports
     * multifactor. One with no accepted evaluation adds nothing but its time.
     *
     * @return void
     */
    public function testAnExternalProofCountsOnlyOnceItsEvidenceWasAccepted(): void
    {
        $external = 'urn:sinemacula:amr:external_provider';
        $first    = self::row(ProofKind::FIRST_FACTOR, [$external], false, '2026-04-06 12:00:00');

        self::assertSame([$external, 'mfa'], (new ProofHistory([self::row(ProofKind::FIRST_FACTOR, [$external], true, '2026-04-06 12:00:00', true)]))->methods());
        self::assertSame([$external], (new ProofHistory([self::row(ProofKind::FIRST_FACTOR, [$external], false, '2026-04-06 12:00:00', true)]))->methods());

        $unaccepted = new ProofHistory([$first, self::row(ProofKind::EXTERNAL_REAUTHENTICATION, ['hwk'], true, '2026-04-06 12:10:00')]);

        self::assertSame([$external], $unaccepted->methods());
        self::assertSame('2026-04-06 12:10:00', $unaccepted->authenticatedAt()?->format('Y-m-d H:i:s'));

        $additional  = self::row(ProofKind::EXTERNAL_REAUTHENTICATION, ['hwk'], false, '2026-04-06 12:10:00', true);
        $multifactor = self::row(ProofKind::EXTERNAL_REAUTHENTICATION, ['hwk'], true, '2026-04-06 12:10:00', true);

        self::assertSame([$external, 'hwk'], (new ProofHistory([$first, $additional]))->methods());
        self::assertSame([$external, 'hwk', 'mfa'], (new ProofHistory([$first, $multifactor]))->methods());
    }

    /**
     * One summary row.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  list<string>  $methods
     * @param  bool  $multifactor
     * @param  string  $at
     * @param  ?bool  $accepted
     * @return array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, accepted: bool, at: \Carbon\CarbonImmutable}
     */
    private static function row(ProofKind $kind, array $methods, bool $multifactor, string $at, ?bool $accepted = null): array
    {
        return ['kind' => $kind, 'methods' => $methods, 'multifactor' => $multifactor, 'accepted' => $accepted ?? $kind->isAdditional(), 'at' => CarbonImmutable::parse($at)];
    }
}
