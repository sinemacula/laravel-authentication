<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;

/**
 * Unit tests for the opt-in `ActivationPolicy`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActivationPolicy::class)]
final class ActivationPolicyTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A subject without the `CanBeActive` capability is active: activation is
     * opt-in, so an ordinary model with no activation column authenticates.
     *
     * @return void
     */
    public function testSubjectWithoutActivationCapabilityIsActive(): void
    {
        self::assertTrue(ActivationPolicy::isActive(\Mockery::mock(Principal::class)));
    }

    /**
     * A `CanBeActive` subject that reports active passes.
     *
     * @return void
     */
    public function testCanBeActiveSubjectReportingActiveIsActive(): void
    {
        $subject = \Mockery::mock(CanBeActive::class);
        $subject->shouldReceive('isActive')->once()->andReturnTrue();

        self::assertTrue(ActivationPolicy::isActive($subject));
    }

    /**
     * A `CanBeActive` subject that reports inactive fails.
     *
     * @return void
     */
    public function testCanBeActiveSubjectReportingInactiveIsNotActive(): void
    {
        $subject = \Mockery::mock(CanBeActive::class);
        $subject->shouldReceive('isActive')->once()->andReturnFalse();

        self::assertFalse(ActivationPolicy::isActive($subject));
    }
}
