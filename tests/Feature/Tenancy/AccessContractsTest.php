<?php

declare(strict_types = 1);

namespace Tests\Feature\Tenancy;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\PrincipalAdmission;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Admission\TenantAdmission;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\TestCase;

/**
 * Feature tests for the access contracts through the package's sign-in, listing
 * and refresh flows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalAdmission::class)]
#[CoversClass(TenantAdmission::class)]
#[CoversClass(SignInAdmission::class)]
final class AccessContractsTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Create the identity, member and tenant tables.
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
     * With the shipped defaults a member signs in to any application as its
     * membership, in the membership's tenant, and is listed it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultsAdmitAnyPrincipalInItsOwnTenant(): void
    {
        [$member, $membership] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertIsModel($membership, $session->principal);
        $listed = $this->sessions('members')->principals($member);

        self::assertSame([$membership->getKey()], array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $listed));
    }

    /**
     * An application access refusal keeps the principal out as
     * `principal_ineligible`, writing nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnApplicationAccessRefusalKeepsThePrincipalOut(): void
    {
        [$member] = $this->seedMember();

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (string $application): bool => $application === 'members'));

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            FailureReason::PRINCIPAL_INELIGIBLE,
            $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->reason,
        );
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertFalse($this->freshGuard('members')->attempt(self::credentials('member@example.test')));
        self::assertSame([], $this->sessions('members')->principals($member));
        self::assertSame(0, Session::query()->count());

        $this->seedIdentity();

        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
    }

    /**
     * A refresh is refused as `principal_ineligible` while the application
     * access refuses the principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshIsHeldToTheApplicationAccess(): void
    {
        $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($session);

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (): bool => true));

        $refused = self::sessionsOf($this->freshGuard('members'))->refresh(self::bodyToken($session->tokens), self::requestClient());

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $refused->reason);
        self::assertNull(Session::query()->sole()->getRevokedAt());

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (): bool => false));

        self::assertTrue(
            self::sessionsOf($this->freshGuard('members'))->refresh(
                self::bodyToken($session->tokens),
                self::requestClient(),
            )->isRefreshed(),
        );
    }

    /**
     * A tenant access refusal of the principal's own tenant refuses the sign-in
     * as `tenant_ineligible`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantAccessRefusalOfTheDefaultRefusesTheSignIn(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $access = new class implements TenantAccess {
            /** @var list<array{0: mixed, 1: mixed}> The principal and tenant identifiers asked about. */
            public array $asked = [];

            /**
             * Refuse every tenant, recording what was asked.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
             * @return bool
             */
            #[\Override]
            public function mayActIn(Principal $principal, ?Tenant $tenant): bool
            {
                $this->asked[] = [$principal->getPrincipalIdentifier(), $tenant?->getTenantIdentifier()];

                return false;
            }
        };

        app()->instance(TenantAccess::class, $access);

        $result = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext());

        self::assertSame(FailureReason::TENANT_INELIGIBLE, $result->reason);
        self::assertSame([[$membership->getKey(), $tenant->getKey()]], $access->asked);
        self::assertSame(0, Session::query()->count());
        self::assertNull(Auth::guard('members')->user());
    }

    /**
     * Configure the session guards.
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
