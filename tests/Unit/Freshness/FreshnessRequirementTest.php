<?php

declare(strict_types = 1);

namespace Tests\Unit\Freshness;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * Unit tests for a freshness requirement: what it keeps, the shape its
 * constructor checks, which kinds it takes, and the stricter of two.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessRequirement::class)]
#[CoversClass(Operations::class)]
final class FreshnessRequirementTest extends TestCase
{
    /**
     * A requirement keeps its age, kinds and flags, asks for neither flag by
     * default, and takes only the kinds it lists.
     *
     * @return void
     */
    public function testARequirementKeepsWhatItAsks(): void
    {
        $plain = new FreshnessRequirement(1, [ProofKind::FIRST_FACTOR]);
        $flags = new FreshnessRequirement(86400, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], true, true);

        self::assertSame([1, [ProofKind::FIRST_FACTOR], false, false], [$plain->maxAgeSeconds, $plain->proofs, $plain->multifactor, $plain->phishingResistant]);
        self::assertSame([86400, true, true], [$flags->maxAgeSeconds, $flags->multifactor, $flags->phishingResistant]);
        self::assertTrue($flags->takes(ProofKind::RECOVERY_CODE));
        self::assertFalse($flags->takes(ProofKind::FIRST_FACTOR));
        self::assertSame(86400, FreshnessRequirement::MAX_AGE_SECONDS);
    }

    /**
     * Rows of `[age, kinds, message]` a requirement refuses.
     *
     * @return iterable<string, array{0: int, 1: array<array-key, mixed>, 2: string}>
     */
    public static function provideRefused(): iterable
    {
        $age   = 'A freshness requirement\'s maximum age must be from 1 to 86400 seconds.';
        $kinds = 'A freshness requirement must take a list of distinct proof kinds, at least one.';

        yield from [
            'no age'          => [0, [ProofKind::FIRST_FACTOR], $age],
            'an age too long' => [86401, [ProofKind::FIRST_FACTOR], $age],
            'no kinds'        => [900, [], $kinds],
            'a kind twice'    => [900, [ProofKind::FIRST_FACTOR, ProofKind::FIRST_FACTOR], $kinds],
            'a kind by value' => [900, ['first_factor'], $kinds],
            'another enum'    => [900, [ProofKind::FIRST_FACTOR, ChannelKind::PASSWORD], $kinds],
            'a map of kinds'  => [900, ['first' => ProofKind::FIRST_FACTOR], $kinds],
        ];
    }

    /**
     * An age outside a day, or kinds that are not a list of distinct kinds, are
     * refused.
     *
     * @param  int  $age
     * @param  array<array-key, mixed>  $kinds
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefused')]
    public function testARequirementRefusesWhatItCannotMean(int $age, array $kinds, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new FreshnessRequirement($age, $kinds);
    }

    /**
     * The stricter of two keeps the shorter age, the kinds both take in the
     * first one's order, and each flag either asks for, whichever way round.
     *
     * @return void
     */
    public function testTheStricterOfTwoKeepsTheShorterAgeTheCommonKindsAndEitherFlag(): void
    {
        $configured = new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR, ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE]);
        $caller     = new FreshnessRequirement(300, [ProofKind::RECOVERY_CODE, ProofKind::ADDITIONAL_FACTOR], true);
        $phishing   = new FreshnessRequirement(1200, [ProofKind::ADDITIONAL_FACTOR], phishingResistant: true);

        $stricter = $configured->stricter($caller);

        self::assertNotNull($stricter);
        self::assertSame(
            [300, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], true, false],
            [$stricter->maxAgeSeconds, $stricter->proofs, $stricter->multifactor, $stricter->phishingResistant],
        );

        $reversed = $caller->stricter($configured);

        self::assertNotNull($reversed);
        self::assertSame([300, [ProofKind::RECOVERY_CODE, ProofKind::ADDITIONAL_FACTOR], true], [$reversed->maxAgeSeconds, $reversed->proofs, $reversed->multifactor]);

        $both = $configured->stricter($phishing);

        self::assertNotNull($both);
        self::assertSame([900, [ProofKind::ADDITIONAL_FACTOR], false, true], [$both->maxAgeSeconds, $both->proofs, $both->multifactor, $both->phishingResistant]);
    }

    /**
     * Two requirements that take no kind in common have no stricter one:
     * nothing could meet both.
     *
     * @return void
     */
    public function testTwoRequirementsWithNoKindInCommonHaveNoStricter(): void
    {
        $first = new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR]);

        self::assertNull($first->stricter(new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR])));
    }

    /**
     * A requirement of an age alone takes every proof kind and asks for no
     * flag.
     *
     * @return void
     */
    public function testARequirementOfAnAgeAloneTakesEveryKind(): void
    {
        $within = FreshnessRequirement::within(300);

        self::assertSame([300, ProofKind::cases(), false, false], [$within->maxAgeSeconds, $within->proofs, $within->multifactor, $within->phishingResistant]);

        $configured = new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], true);

        self::assertEquals(new FreshnessRequirement(300, [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], true), $configured->stricter($within));

        $this->expectException(\InvalidArgumentException::class);

        FreshnessRequirement::within(0);
    }

    /**
     * The operations the package names.
     *
     * @return void
     */
    public function testThePackagesOperations(): void
    {
        self::assertSame(
            ['identifier_change', 'password_establishment', 'factor_change'],
            [Operations::IDENTIFIER_CHANGE, Operations::PASSWORD_ESTABLISHMENT, Operations::FACTOR_CHANGE],
        );
    }
}
