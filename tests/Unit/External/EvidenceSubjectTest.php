<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\EvidenceSubject;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

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
     * The subject names whose evidence is judged, for which tenant and when, as
     * given.
     *
     * @return void
     */
    public function testTheSubjectNamesWhoseEvidenceIsJudgedForWhomAndWhen(): void
    {
        $identity = new PlainIdentityFixture(7);
        $tenant   = new PlainTenantFixture(3);
        $now      = CarbonImmutable::parse('2026-04-06 12:00:00');
        $subject  = new EvidenceSubject($identity, 'api', 'conn-a', $now, $tenant);

        self::assertSame([$identity, 'api', 'conn-a', $now, $tenant], [$subject->identity, $subject->application, $subject->connectionId, $subject->now, $subject->tenant]);
        self::assertNull((new EvidenceSubject($identity, 'api', 'conn-a', $now))->tenant);
    }
}
