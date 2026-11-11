<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Reauthenticated;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Integration tests of external reauthentication against a real database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalReauthentication::class)]
final class ExternalReauthenticationTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The session's link is matched byte for byte.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionsLinkIsMatchedByteForByte(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->sessions()->signInExternally(
            $this->linkedResult($identity, 'conn-a', 'link-a', 'subject-a', authenticatedAt: $this->now),
            self::requestContext(),
        )->session;

        self::assertNotNull($session);

        $others = [
            $this->linkedResult($identity, 'conn-a', 'LINK-A', 'subject-b', authenticatedAt: $this->now),
            $this->linkedResult($identity, 'conn-a', 'link-a ', 'subject-c', authenticatedAt: $this->now),
            $this->linkedResult($identity, 'CONN-A', 'link-a', 'subject-a', authenticatedAt: $this->now),
            $this->linkedResult($identity, 'conn-a ', 'link-a', 'subject-a', authenticatedAt: $this->now),
        ];

        foreach ($others as $result) {
            self::assertSame(FailureReason::LINK_MISMATCH, $this->sessions()->reauthenticateExternally($session->record->getKey(), $result, self::requestClient())->reason);
        }

        $own = $this->linkedResult($identity, 'conn-a', 'link-a', 'subject-a', authenticatedAt: $this->now);

        self::assertTrue($this->sessions()->reauthenticateExternally($session->record->getKey(), $own, self::requestClient())->isIssued());
    }

    /**
     * The reauthentication follows the adapter's transaction.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReauthenticationFollowsTheAdaptersTransaction(): void
    {
        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, authenticatedAt: $this->now);
        $session  = $this->sessions()->signInExternally($result, self::requestContext())->session;

        self::assertNotNull($session);

        $this->recordEvents([Reauthenticated::class]);

        DB::beginTransaction();

        self::assertTrue($this->sessions()->reauthenticateExternally($session->record->getKey(), $result, self::requestClient())->isIssued());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(0, DB::table('authentication_proofs')->where('kind', 'external_reauthentication')->count());

        DB::beginTransaction();

        self::assertTrue($this->sessions()->reauthenticateExternally($session->record->getKey(), $result, self::requestClient())->isIssued());
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([Reauthenticated::class], $this->recordedClasses());
        self::assertSame(1, DB::table('authentication_proofs')->where('kind', 'external_reauthentication')->count());
    }

    /**
     * Register the guards.
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
