<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ManagesDevices;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RevokesOnSecurityChanges;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\CutoffIdentity;

/**
 * Query-budget contracts for signing out and revoking: a sign-out of a bound
 * device is one conditional `UPDATE`; revoking one device of a list is the
 * owner-scoped read and that `UPDATE`; a bulk revocation, which every security
 * change and a sign-out everywhere make, reads its devices a chunk at a time
 * and writes one `UPDATE` per device and one `DELETE` of the scope's pending
 * sign-ins, a principal's after one read of its owner, a tenant's for each
 * principal after reading its tenant, and an identity's that keeps a cutoff
 * after the one conditional `UPDATE` that moves it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(DeviceRevocations::class)]
#[CoversTrait(ManagesDevices::class)]
#[CoversTrait(RevokesOnSecurityChanges::class)]
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

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');

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
     * Revoking a 3D principal's two devices reads its owner afresh (to know
     * whether it can hold devices) and one chunk, and writes two revocations
     * and the pending sign-ins' delete.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalsRevocationReadsItsOwnerOnceMore(): void
    {
        [, $membership] = $this->seedMember();

        $this->memberSignIn();
        $this->memberSignIn();

        $sessions = $this->sessions('members');

        self::assertSame(2, $this->assertQueryBudget(2, 3, static fn (): int => $sessions->revokePrincipalDevices($membership, RevocationReason::REVOKED)));
    }

    /**
     * Rows of `[the security change]`: each ends every session of the identity
     * through one bulk revocation.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int}>
     */
    public static function provideIdentityChanges(): iterable
    {
        yield 'a changed password' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->passwordChanged($identity)];
        yield 'a reset password' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->passwordReset($identity)];
        yield 'a removed factor' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->factorRemoved($identity)];
        yield 'a deactivated identity' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->identityDeactivated($identity)];
    }

    /**
     * A security change of an identity with three devices costs what a bulk
     * revocation costs: one chunk read, an update per device and the pending
     * sign-ins' delete.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SessionService, \SineMacula\Laravel\Authentication\Contracts\Identity): int  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIdentityChanges')]
    public function testASecurityChangeOfAnIdentityCostsABulkRevocation(\Closure $change): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();
        $this->signIn();

        $sessions = $this->sessions();

        self::assertSame(3, $this->assertQueryBudget(1, 4, static fn (): int => $change($sessions, $identity)));
    }

    /**
     * A changed password that keeps the device it was made from reads the same
     * chunk and leaves that device unwritten.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangedPasswordKeepingItsDeviceWritesOneUpdateFewer(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        $kept     = $this->signIn()->device;
        $sessions = $this->sessions();

        self::assertSame(2, $this->assertQueryBudget(1, 3, static fn (): int => $sessions->passwordChanged($identity, $kept)));
    }

    /**
     * A deactivated principal costs what revoking its devices costs: its owner
     * read afresh, one chunk, an update per device and the pending sign-ins'
     * delete.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeactivatedPrincipalCostsItsRevocation(): void
    {
        [, $membership] = $this->seedMember();

        $this->memberSignIn();
        $this->memberSignIn();

        $sessions = $this->sessions('members');

        self::assertSame(2, $this->assertQueryBudget(2, 3, static fn (): int => $sessions->principalDeactivated($membership)));
    }

    /**
     * Rows of `[principals, reads, writes]`: a tenant's deactivation over that
     * many principals, each with one session, and its cost.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideTenantPrincipals(): iterable
    {
        yield 'one principal' => [1, 3, 2];
        yield 'three principals' => [3, 9, 6];
    }

    /**
     * A tenant's deactivation reads each principal's tenant, owner and devices,
     * and writes each device's revocation and each principal's pending
     * sign-ins' delete: three reads and two writes for each principal with one
     * session.
     *
     * @param  int  $count
     * @param  int  $reads
     * @param  int  $writes
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTenantPrincipals')]
    public function testATenantsDeactivationCostsTheSameForEachPrincipal(int $count, int $reads, int $writes): void
    {
        $tenant     = ActivatableTenant::query()->create(['name' => 'Tenant', 'is_active' => true]);
        $principals = [];

        for ($member = 0; $member < $count; $member++) {
            [, $principals[]] = $this->seedMember('member' . $member . '@example.test', $tenant);

            self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member' . $member . '@example.test'))->isSignedIn());
        }

        $sessions = $this->sessions('members');

        self::assertSame($count, $this->assertQueryBudget($reads, $writes, static fn (): int => $sessions->tenantDeactivated($tenant, $principals)));
    }

    /**
     * Signing out everywhere but the request's own device reads the identity's
     * other devices in one chunk, revokes them and deletes the pending
     * sign-ins.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutEverywhereButHereRevokesTheOthers(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        $current = $this->signIn();
        $guard   = $this->freshGuard();

        $guard->login($identity, $identity, $current->device);

        $sessions = $guard->sessions();

        self::assertSame(2, $this->assertQueryBudget(1, 3, static fn (): int => $sessions->signOutEverywhere(true)));
    }

    /**
     * A security change of an identity that keeps a "tokens valid after" cutoff
     * moves the cutoff in one more write before the bulk revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeOfACutoffIdentityMovesItsCutoffInOneMoreWrite(): void
    {
        $identity = $this->seedCutoffIdentity();

        $this->cutoffSignIn();
        $this->cutoffSignIn();

        $sessions = $this->sessions('cutoff');

        self::assertSame(2, $this->assertQueryBudget(1, 4, static fn (): int => $sessions->passwordChanged($identity)));
    }

    /**
     * Signing out everywhere but a device-less request's own session leaves the
     * cutoff where it is, so it costs the bulk revocation alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeepingADevicelessSessionWritesNoCutoff(): void
    {
        $identity = $this->seedCutoffIdentity();

        $this->cutoffSignIn();
        $this->cutoffSignIn();

        $guard = $this->freshGuard('cutoff');

        $guard->login($identity, $identity);

        $sessions = $guard->sessions();

        self::assertSame(2, $this->assertQueryBudget(1, 3, static fn (): int => $sessions->signOutEverywhere(true)));
        self::assertNull($identity->fresh()?->getTokensValidAfter());
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.cutoff', ['driver' => 'model', 'model' => CutoffIdentity::class]);
        $config->set('auth.guards.cutoff', ['driver' => 'jwt', 'provider' => 'cutoff', 'audience' => ['methods' => ['password']]]);
    }

    /**
     * Persist an identity that records no cutoff yet.
     *
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function seedCutoffIdentity(): CutoffIdentity
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => 'cutoff@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        return $identity;
    }

    /**
     * Sign the seeded cutoff identity in on the `cutoff` guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function cutoffSignIn(): void
    {
        self::assertTrue($this->sessions('cutoff')->signIn('password', self::credentials('cutoff@example.test'))->isSignedIn());
    }

    /**
     * Sign the seeded member in on the `members` guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    private function memberSignIn(): void
    {
        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());
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
