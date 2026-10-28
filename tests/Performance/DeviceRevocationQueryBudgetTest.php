<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;

/**
 * Query-budget contracts for signing out and revoking: a sign-out of a bound
 * device is one conditional `UPDATE`; revoking one device of a list is the
 * owner-scoped read and that `UPDATE`; a bulk revocation reads its devices a
 * chunk at a time and writes one `UPDATE` per device and one `DELETE` of the
 * scope's pending sign-ins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(DeviceRevocations::class)]
final class DeviceRevocationQueryBudgetTest extends PerformanceContractTestCase
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
     * Signing out a request bound to its device writes the one revocation and
     * reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutIsOneUpdate(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();
        $guard    = $this->freshGuard();

        $guard->login($identity, $identity, $session->device);

        self::assertTrue($this->assertQueryBudget(0, 1, static fn (): bool => $guard->sessions()->signOut()));
    }

    /**
     * Revoking one device of the owner reads it through the owner's relation
     * and writes the one revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingOneDeviceIsOneReadAndOneUpdate(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();
        $sessions = $this->sessions();
        $id       = IdentifierCoercion::stringify($session->device->getDeviceIdentifier());

        self::assertTrue($this->assertQueryBudget(1, 1, static fn (): bool => $sessions->revokeDevice($identity, $id, RevocationReason::REVOKED)));
    }

    /**
     * Revoking three devices of an identity reads one chunk and writes three
     * revocations and the pending sign-ins' delete.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationIsAReadPerChunkAnUpdatePerDeviceAndOneDelete(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();
        $this->signIn();

        $sessions = $this->sessions();

        self::assertSame(3, $this->assertQueryBudget(1, 4, static fn (): int => $sessions->revokeDevices($identity, RevocationReason::REVOKED)));
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

    /**
     * Sign the seeded identity in.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }
}
