<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Pagination\LengthAwarePaginator;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Sessions\ActiveDevices;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\InteractsWithSessions;

/**
 * Query-budget contracts for the device list: a page is one count and one
 * select, however many devices it holds, and nothing is written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(ActiveDevices::class)]
final class DeviceListingQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Listing a page of five devices, on a guard already bound to one of them,
     * reads twice and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPageIsOneCountAndOneSelect(): void
    {
        $identity = $this->seedIdentity();

        for ($index = 0; $index < 5; $index++) {
            $this->sessions()->signIn('password', self::credentials());
        }

        $sessions = $this->sessions();

        $sessions->signIn('password', self::credentials());

        $page = $this->assertQueryBudget(2, 0, static fn (): LengthAwarePaginator => $sessions->devices($identity, 4));

        self::assertSame(6, $page->total());
        self::assertCount(4, $page->items());
    }

    /**
     * An identity with no active device costs the count alone.
     *
     * @return void
     */
    public function testAnEmptyListIsOneCount(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        self::assertSame(0, $this->assertQueryBudget(1, 0, static fn (): LengthAwarePaginator => $sessions->devices($identity))->total());
    }

    /**
     * Register the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }
}
