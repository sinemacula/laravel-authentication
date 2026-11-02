<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;

/**
 * Unit tests for a pending session as the session service hands it out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSession::class)]
final class PendingSessionTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The pending session carries its id, guard, identity, principal, active
     * tenant, what it waits on, its method, when its credential expires, its
     * record and the principals to choose from.
     *
     * @return void
     */
    public function testCarriesWhatItWasGiven(): void
    {
        $identity   = \Mockery::mock(Identity::class);
        $principal  = \Mockery::mock(Principal::class);
        $tenant     = \Mockery::mock(Tenant::class);
        $session    = \Mockery::mock(Session::class);
        $expiresAt  = CarbonImmutable::parse('2026-04-06 12:05:00');
        $principals = [\Mockery::mock(Principal::class)];

        $pending = new PendingSession('session-1', 'api', $identity, $principal, $tenant, [PendingRequirement::MFA], 'password', $expiresAt, $session, $principals);

        self::assertSame('session-1', $pending->id);
        self::assertSame('api', $pending->guard);
        self::assertSame($identity, $pending->identity);
        self::assertSame($principal, $pending->principal);
        self::assertSame($tenant, $pending->tenant);
        self::assertSame([PendingRequirement::MFA], $pending->requires);
        self::assertSame('password', $pending->method);
        self::assertSame($expiresAt, $pending->expiresAt);
        self::assertSame($session, $pending->session);
        self::assertSame($principals, $pending->principals);
        self::assertSame([], (new PendingSession('s', 'api', $identity, null, null, [PendingRequirement::PRINCIPAL], 'password', $expiresAt, $session))->principals);
    }

    /**
     * Rows of `[requires, actions allowed]`: what each order of requirements
     * lets the credential do, which is only what the first one allows.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>, 1: list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction>}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideRequirements(): iterable
    {
        yield 'a factor alone' => [[PendingRequirement::MFA], PendingRequirement::MFA->actions()];
        yield 'a factor, then a choice' => [[PendingRequirement::MFA, PendingRequirement::PRINCIPAL], PendingRequirement::MFA->actions()];
        yield 'a choice alone' => [[PendingRequirement::PRINCIPAL], PendingRequirement::PRINCIPAL->actions()];
    }

    /**
     * The credential allows exactly the first outstanding requirement's
     * actions: no principal is listed or chosen while a factor is owed, and no
     * factor action is allowed once only the choice is left.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @param  list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction>  $allowed
     * @return void
     */
    #[DataProvider('provideRequirements')]
    public function testAllowsOnlyTheFirstRequirementsActions(array $requires, array $allowed): void
    {
        $pending = new PendingSession(
            'session-1',
            'api',
            \Mockery::mock(Identity::class),
            null,
            null,
            $requires,
            'password',
            CarbonImmutable::now(),
            \Mockery::mock(Session::class),
        );

        self::assertSame($allowed, $pending->actions());

        foreach (PendingAction::cases() as $action) {
            self::assertSame(in_array($action, $allowed, true), $pending->allows($action), $action->value);
        }
    }
}
