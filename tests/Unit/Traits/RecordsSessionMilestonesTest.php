<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Concerns\RecordsSessionMilestones;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubUncastDevice;

/**
 * Unit tests for the accessors behind when a device's session started and when
 * it last switched the principal it acts as.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(RecordsSessionMilestones::class)]
final class RecordsSessionMilestonesTest extends TestCase
{
    /**
     * Both times are read as values, with or without a `datetime` cast, and a
     * session that never switched reads no switch time.
     *
     * @return void
     */
    public function testReadsTheRecordedTimes(): void
    {
        $device = (new StubUncastDevice)->forceFill(['signed_in_at' => '2026-04-06 12:00:00', 'principal_switched_at' => '2026-04-06 12:05:00']);
        $never  = (new StubUncastDevice)->forceFill(['signed_in_at' => '2026-04-06 12:00:00', 'principal_switched_at' => null]);

        self::assertSame('2026-04-06 12:00:00', $device->getSignedInAt()?->format('Y-m-d H:i:s'));
        self::assertSame('2026-04-06 12:05:00', $device->getPrincipalSwitchedAt()?->format('Y-m-d H:i:s'));
        self::assertNull($never->getPrincipalSwitchedAt());
    }

    /**
     * A device loaded without its start time is reported rather than read as a
     * session with no start.
     *
     * @return void
     */
    public function testAStartTimeThatWasNotLoadedIsReported(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('`signed_in_at`');

        (new StubDevice)->getSignedInAt();
    }

    /**
     * A device loaded without its switch time is reported rather than read as a
     * session that never switched.
     *
     * @return void
     */
    public function testASwitchTimeThatWasNotLoadedIsReported(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('getPrincipalSwitchedAtName()');

        (new StubDevice)->getPrincipalSwitchedAt();
    }

    /**
     * The column names are the shipped migration's.
     *
     * @return void
     */
    public function testNamesTheShippedColumns(): void
    {
        $device = new StubDevice;

        self::assertSame('signed_in_at', $device->getSignedInAtName());
        self::assertSame('principal_switched_at', $device->getPrincipalSwitchedAtName());
    }
}
