<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for what the evidence policy judges evidence for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EvidenceSubject::class)]
final class EvidenceSubjectTest extends TestCase
{
    /**
     * The subject names the identity, the application, the connection that
     * asserted the evidence and the time it is judged at, as given.
     *
     * @return void
     */
    public function testTheSubjectNamesWhoseEvidenceIsJudgedAndWhen(): void
    {
        $identity = new PlainIdentityFixture(7);
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $subject  = new EvidenceSubject($identity, 'api', 'conn-a', $now);

        self::assertSame([$identity, 'api', 'conn-a', $now], [$subject->identity, $subject->application, $subject->connectionId, $subject->now]);
    }
}
