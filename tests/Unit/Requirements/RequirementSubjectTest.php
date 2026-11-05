<?php

declare(strict_types = 1);

namespace Tests\Unit\Requirements;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the requirement subject's bounded proof query and the default
 * check, which meets nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequirementSubject::class)]
#[CoversClass(MeetNoRequirement::class)]
final class RequirementSubjectTest extends TestCase
{
    /**
     * The subject hands its query's arguments to the package's reader, at
     * either end of the limit's range, and returns what it reads, and holds the
     * first factor however the query answers.
     *
     * @return void
     */
    public function testTheQueryIsTheReadersAnswer(): void
    {
        $now   = CarbonImmutable::parse('2026-04-06 12:00:00');
        $first = SignInProof::unattested('password', $now)->recorded();
        $asked = [];

        $reader = static function (?CarbonImmutable $since, ?array $kinds, int $limit) use (&$asked, $first): array {
            $asked[] = [$since, $kinds, $limit];

            return [$first];
        };

        $subject = new RequirementSubject(new PlainIdentityFixture(7), 'api', null, $first, $now, $reader);

        self::assertSame([$first], $subject->proofs($now->subMinute(), [ProofKind::ADDITIONAL_FACTOR], RequirementSubject::MAX_LIMIT));
        self::assertEquals([[$now->subMinute(), [ProofKind::ADDITIONAL_FACTOR], 200]], $asked);

        $subject->proofs();
        $subject->proofs(limit: 1);

        self::assertEquals([null, null, 50], $asked[1]);
        self::assertEquals([null, null, 1], $asked[2]);
        self::assertSame($first, $subject->firstFactor);
        self::assertSame('api', $subject->application);
        self::assertNull($subject->session);
    }

    /**
     * A mutable time reaches the reader as an immutable copy of the same
     * instant, and the time given is left as it was.
     *
     * @return void
     */
    public function testAMutableTimeReachesTheReaderAsAnImmutableCopy(): void
    {
        $now   = CarbonImmutable::parse('2026-04-06 12:00:00');
        $first = SignInProof::unattested('password', $now)->recorded();
        $given = Carbon::parse('2026-04-06 07:59:30.250000', 'America/New_York');
        $asked = [];

        $reader = static function (?CarbonImmutable $since) use (&$asked): array {
            $asked[] = $since;

            return [];
        };

        $subject = new RequirementSubject(new PlainIdentityFixture(7), 'api', null, $first, $now, $reader);

        self::assertSame([], $subject->proofs($given));
        self::assertCount(1, $asked);
        self::assertInstanceOf(CarbonImmutable::class, $asked[0]);
        self::assertTrue($asked[0]->equalTo($given));
        self::assertSame('2026-04-06 07:59:30.250000 America/New_York', $given->format('Y-m-d H:i:s.u e'));
    }

    /**
     * Asking for no proofs, or for more than the cap, is refused before the
     * reader is called.
     *
     * @return void
     */
    public function testALimitOutsideItsRangeIsRefused(): void
    {
        $now     = CarbonImmutable::parse('2026-04-06 12:00:00');
        $subject = new RequirementSubject(new PlainIdentityFixture(7), 'api', null, SignInProof::unattested('password', $now)->recorded(), $now, static function (): array {
            self::fail('The reader must not be called.');
        });

        foreach ([0, RequirementSubject::MAX_LIMIT + 1] as $limit) {
            try {
                $subject->proofs(limit: $limit);

                self::fail('Expected the limit to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('A requirement subject returns between 1 and 200 proofs at a time.', $exception->getMessage());
            }
        }
    }

    /**
     * The default check leaves every kind of the requirement unmet, so a
     * requirement nothing has been bound to judge fails closed.
     *
     * @return void
     */
    public function testTheDefaultCheckMeetsNothing(): void
    {
        $now     = CarbonImmutable::parse('2026-04-06 12:00:00');
        $subject = new RequirementSubject(new PlainIdentityFixture(7), 'api', null, SignInProof::unattested('password', $now)->recorded(), $now, static fn (): array => []);

        $evaluation = (new MeetNoRequirement)->evaluate($subject, new Requirement(new RequirementPart, new RequirementPart));

        self::assertFalse($evaluation->isMet());
        self::assertSame(['additional_verification', 'multifactor'], array_column($evaluation->unmet, 'value'));
    }
}
