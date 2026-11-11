<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Pagination\LengthAwarePaginator;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use Tests\Concerns\InteractsWithSessions;

/**
 * Query-budget contracts for listing a page of sessions and looking one session
 * up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(ActiveSessions::class)]
final class SessionListingQueryBudgetTest extends PerformanceContractTestCase
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
     * Listing a page of five sessions, on a guard already bound to one of them,
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
            $this->sessions()->signIn('password', self::credentials(), self::requestContext());
        }

        $sessions = $this->sessions();

        $sessions->signIn('password', self::credentials(), self::requestContext());

        $page = $this->assertQueryBudget(2, 0, static fn (): LengthAwarePaginator => $sessions->sessions($identity, 4));

        self::assertSame(6, $page->total());
        self::assertCount(4, $page->items());
    }

    /**
     * An identity with no active session costs the count alone.
     *
     * @return void
     */
    public function testAnEmptyListIsOneCount(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        self::assertSame(0, $this->assertQueryBudget(1, 0, static fn (): LengthAwarePaginator => $sessions->sessions($identity))->total());
    }

    /**
     * Finding one session, on a guard already bound to one of five, reads once
     * and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneSessionIsOneSelect(): void
    {
        $identity = $this->seedIdentity();

        for ($index = 0; $index < 4; $index++) {
            $this->sessions()->signIn('password', self::credentials(), self::requestContext());
        }

        $sessions = $this->sessions();
        $bound    = $sessions->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($bound);

        $id    = $bound->record->getSessionIdentifier();
        $found = $this->assertQueryBudget(1, 0, static fn (): ?SessionSummary => $sessions->session($identity, $id));

        self::assertTrue($found?->current);
    }

    /**
     * An identifier that cannot be a session key costs nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierThatCannotBeAKeyCostsNothing(): void
    {
        $identity = $this->seedIdentity();
        $sessions = $this->sessions();

        $sessions->signIn('password', self::credentials(), self::requestContext());

        self::assertNull($this->assertQueryBudget(0, 0, static fn (): ?SessionSummary => $sessions->session($identity, 'not-a-uuid')));
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
