<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\MassPrunable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Concerns\PrunesDevices;
use SineMacula\Laravel\Authentication\Database\DeviceRetention;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;

/**
 * Feature tests for the retention `PrunesDevices` reads, and the query it
 * builds, on the shipped device model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceRetention::class)]
#[CoversTrait(PrunesDevices::class)]
final class PrunesDevicesTest extends TestCase
{
    /**
     * Release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * The shipped model is mass prunable through the trait, which is how
     * `model:prune` recognises it.
     *
     * @return void
     */
    public function testTheShippedModelIsMassPrunable(): void
    {
        self::assertContains(MassPrunable::class, class_uses_recursive(Device::class));
    }

    /**
     * The query selects devices revoked, idle-expired or absolutely expired at
     * or before now less the retention, grouped so a scope added to it cannot
     * widen it, with 30 days when nothing is configured.
     *
     * @return void
     */
    public function testTheQueryCutsOffAtNowLessTheRetention(): void
    {
        Carbon::setTestNow(Carbon::parse('2027-01-15 10:00:00.750'));

        config()->set('authentication.device', ['model' => Device::class, 'table' => 'devices']);

        $query = (new Device)->prunable()->where('guard', 'api');

        self::assertSame(
            'select * from devices where (revoked_at <= ? or idle_expires_at <= ? or absolute_expires_at <= ?) and guard = ?',
            str_replace(['"', '`'], '', $query->toSql()),
        );
        self::assertSame(['2026-12-16 10:00:00', '2026-12-16 10:00:00', '2026-12-16 10:00:00', 'api'], $query->getBindings());
    }

    /**
     * Retentions that are accepted, with the cutoff each gives at 2027-01-15
     * 10:00:00.
     *
     * @return iterable<string, array{0: int|string, 1: string}>
     */
    public static function acceptedRetentions(): iterable
    {
        yield 'zero' => [0, '2027-01-15 10:00:00'];
        yield 'zero as a string' => ['0', '2027-01-15 10:00:00'];
        yield 'one' => [1, '2027-01-14 10:00:00'];
        yield 'a digit string' => ['7', '2027-01-08 10:00:00'];
        yield 'four digits' => ['3650', '2017-01-17 10:00:00'];
        yield 'the maximum' => [3650, '2017-01-17 10:00:00'];
    }

    /**
     * Each accepted retention moves the cutoff back that many days.
     *
     * @param  int|string  $days
     * @param  string  $cutoff
     * @return void
     */
    #[DataProvider('acceptedRetentions')]
    public function testAcceptsIntegersAndDigitStringsFromZeroToTenYears(int|string $days, string $cutoff): void
    {
        Carbon::setTestNow(Carbon::parse('2027-01-15 10:00:00'));

        config()->set('authentication.device.prune_after_days', $days);

        self::assertSame([$cutoff, $cutoff, $cutoff], (new Device)->prunable()->getBindings());
    }

    /**
     * Retentions that are refused.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function rejectedRetentions(): iterable
    {
        yield 'negative' => [-1];
        yield 'over ten years' => [3651];
        yield 'over ten years as a string' => ['3651'];
        yield 'five digits' => ['10000'];
        yield 'padded' => ['030'];
        yield 'signed' => ['+7'];
        yield 'negative string' => ['-1'];
        yield 'fraction string' => ['1.5'];
        yield 'float' => [1.5];
        yield 'trailing newline' => ["7\n"];
        yield 'empty' => [''];
        yield 'words' => ['thirty'];
        yield 'null' => [null];
        yield 'boolean' => [true];
        yield 'array' => [[30]];
    }

    /**
     * Any other retention fails closed when pruning runs.
     *
     * @param  mixed  $days
     * @return void
     */
    #[DataProvider('rejectedRetentions')]
    public function testRejectsAnyOtherRetention(mixed $days): void
    {
        config()->set('authentication.device.prune_after_days', $days);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.device.prune_after_days must be an integer from 0 to 3650.');

        (new Device)->prunable();
    }
}
