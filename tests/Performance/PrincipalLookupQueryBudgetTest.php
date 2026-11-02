<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;

/**
 * Query-budget contracts for the lookup of one principal: the identity's
 * principals are read in one query, however many it has, and only the one the
 * identifier names is admitted, so its tenant is the only other read; nothing
 * is written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PendingEvaluation::class)]
final class PrincipalLookupQueryBudgetTest extends PerformanceContractTestCase
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
     * Looking one of four memberships up reads the memberships once and the
     * named one's tenant once, and writes nothing.
     *
     * @return void
     */
    public function testOnePrincipalIsOneCandidateQueryAndItsTenant(): void
    {
        [$member] = $this->seedMember();

        $named = null;

        foreach (['Second', 'Third', 'Fourth'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);
            $named  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        self::assertNotNull($named);

        $sessions = $this->sessions('members');
        $id       = $named->getKey();
        $found    = $this->assertQueryBudget(2, 0, static fn (): ?Principal => $sessions->principal($member, $id));

        self::assertSame($id, $found?->getPrincipalIdentifier());
    }

    /**
     * An identifier none of the memberships has costs the one candidate query.
     *
     * @return void
     */
    public function testAnUnknownPrincipalIsOneCandidateQuery(): void
    {
        [$member] = $this->seedMember();

        $sessions = $this->sessions('members');

        self::assertNull($this->assertQueryBudget(1, 0, static fn (): ?Principal => $sessions->principal($member, 'unknown')));
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
