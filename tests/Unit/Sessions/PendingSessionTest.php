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
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use Tests\Fixtures\Proofs\UndescribedSignInProof;

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
     * record, what its authentication still falls short of, its first factor
     * and the principals to choose from.
     *
     * @return void
     */
    public function testCarriesWhatItWasGiven(): void
    {
        $identity    = \Mockery::mock(Identity::class);
        $principal   = \Mockery::mock(Principal::class);
        $tenant      = \Mockery::mock(Tenant::class);
        $session     = \Mockery::mock(Session::class);
        $expiresAt   = CarbonImmutable::parse('2026-04-06 12:05:00');
        $principals  = [\Mockery::mock(Principal::class)];
        $requirement = new Requirement(phishingResistance: new RequirementPart(300));
        $first       = self::firstFactor();

        $requires = [PendingRequirement::MFA];
        $pending  = new PendingSession('session-1', 'api', $identity, $principal, $tenant, $requires, 'password', $expiresAt, $session, $requirement, $first, $principals);

        self::assertSame('session-1', $pending->id);
        self::assertSame('api', $pending->guard);
        self::assertSame($identity, $pending->identity);
        self::assertSame($principal, $pending->principal);
        self::assertSame($tenant, $pending->tenant);
        self::assertSame([PendingRequirement::MFA], $pending->requires);
        self::assertSame('password', $pending->method);
        self::assertSame($expiresAt, $pending->expiresAt);
        self::assertSame($session, $pending->session);
        self::assertSame($requirement, $pending->requirement);
        self::assertSame($first, $pending->firstFactor);
        self::assertSame($principals, $pending->principals);
        $choice = new PendingSession('s', 'api', $identity, null, null, [PendingRequirement::PRINCIPAL], 'password', $expiresAt, $session, new Requirement, self::firstFactor());

        self::assertSame([], $choice->principals);
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
            new Requirement,
            self::firstFactor(),
        );

        self::assertSame($allowed, $pending->actions());

        foreach (PendingAction::cases() as $action) {
            self::assertSame(in_array($action, $allowed, true), $pending->allows($action), $action->value);
        }
    }

    /**
     * Rows of a limit a pending session never reads proofs with.
     *
     * @return iterable<string, array{0: int}>
     */
    public static function provideLimitsOutOfRange(): iterable
    {
        yield 'none' => [0];
        yield 'one past the most' => [RequirementSubject::MAX_LIMIT + 1];
    }

    /**
     * Its proofs are read a bounded page at a time: a limit outside 1 to the
     * subject's most is refused before anything is read.
     *
     * @param  int  $limit
     * @return void
     */
    #[DataProvider('provideLimitsOutOfRange')]
    public function testReadsItsProofsABoundedPageAtATime(int $limit): void
    {
        $session = \Mockery::mock(Session::class);

        $session->shouldNotReceive('getSessionIdentifier');

        $identity = \Mockery::mock(Identity::class);
        $now      = CarbonImmutable::now();
        $pending  = new PendingSession('s', 'api', $identity, null, null, [PendingRequirement::MFA], 'password', $now, $session, new Requirement, self::firstFactor());

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A pending session returns between 1 and 200 proofs at a time.');

        $pending->proofs(limit: $limit);
    }

    /**
     * The proof of a first factor, as a session records it.
     *
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     */
    private static function firstFactor(): RecordedProof
    {
        return UndescribedSignInProof::of('password', CarbonImmutable::now())->recorded();
    }
}
