<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ChoosesPrincipals;
use SineMacula\Laravel\Authentication\Sessions\PrincipalSwitch;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;

/**
 * Query-budget contracts for choosing and switching principal: a sign-in held
 * for a choice reads the identity and its principals (and each one's tenant)
 * and writes the attempt counters and the pending choice; a switch reads the
 * refresh counters, the device, its owner, the target, its tenant and its
 * owner, writes the one compare-and-swap, and then reads the principal it
 * switched from for the event.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PrincipalSwitch::class)]
#[CoversTrait(ChoosesPrincipals::class)]
final class PrincipalSwitchQueryBudgetTest extends PerformanceContractTestCase
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
     * A switch to another membership reads the refresh counters, the device,
     * its owner, the target, its tenant and its owner, writes the switch, and
     * reads the membership it switched from.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsItsReadsAndOneUpdate(): void
    {
        [$member, , $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $sessions = $this->sessions('members');
        $result   = $this->assertQueryBudget(7, 1, static fn (): SwitchResult => $sessions->switchPrincipal($session->tokens->refreshToken, $second));

        self::assertTrue($result->isSwitched());
    }

    /**
     * A sign-in held for a choice between two memberships reads the identity,
     * its memberships and each one's tenant, and writes the six attempt-counter
     * statements a password sign-in makes and the pending choice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsItsReadsTheCountersAndOneInsert(): void
    {
        $member = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        $sessions = $this->sessions('choosers');
        $result   = $this->assertQueryBudget(4, 7, static fn (): SignInResult => $sessions->signIn('password', self::credentials('chooser@example.test')));

        self::assertTrue($result->requiresPrincipal());
    }

    /**
     * Register the session guards, and a guard over the choosing members.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.choosers', ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
    }
}
