<?php

declare(strict_types = 1);

namespace Tests\Unit\Codes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\DeliveryRefusal;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Unit tests for why the engine delivered no code: the cooldown or the delivery
 * cap, each with a wait of at least one second.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeliveryRefusal::class)]
final class DeliveryRefusalTest extends TestCase
{
    /**
     * A cooldown is not the cap, and the cap is; each keeps its wait, raised to
     * one second when it would be less.
     *
     * @return void
     */
    public function testSaysWhyAndHowLong(): void
    {
        $cooldown  = DeliveryRefusal::cooldown(42);
        $exhausted = DeliveryRefusal::exhausted(900);

        self::assertSame([42, false], [$cooldown->retryAfter, $cooldown->exhausted]);
        self::assertSame([900, true], [$exhausted->retryAfter, $exhausted->exhausted]);
        self::assertSame(
            [1, 1, 1, 1],
            [
                DeliveryRefusal::cooldown(0)->retryAfter,
                DeliveryRefusal::cooldown(-5)->retryAfter,
                DeliveryRefusal::exhausted(0)->retryAfter,
                DeliveryRefusal::cooldown(1)->retryAfter,
            ],
        );
    }

    /**
     * A cooldown is answered `rate_limited` and the cap `deliveries_exhausted`,
     * each with its wait, and reported with the reason of the same name.
     *
     * @return void
     */
    public function testAnswersAndReportsWhy(): void
    {
        $cooldown  = DeliveryRefusal::cooldown(42);
        $exhausted = DeliveryRefusal::exhausted(900);

        self::assertSame([CodeRequestStatus::RATE_LIMITED, 42, FailureReason::RATE_LIMITED], [$cooldown->request()->status, $cooldown->request()->retryAfter, $cooldown->reason()]);
        self::assertSame(
            [CodeRequestStatus::DELIVERIES_EXHAUSTED, 900, FailureReason::DELIVERIES_EXHAUSTED],
            [$exhausted->request()->status, $exhausted->request()->retryAfter, $exhausted->reason()],
        );
    }
}
