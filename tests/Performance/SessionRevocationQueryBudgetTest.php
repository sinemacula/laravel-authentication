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
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\CutoffIdentity;

/**
 * Query-budget contracts for signing out and revoking: a sign-out of a bound
 * session is one conditional `UPDATE`; revoking one session of a list is the
 * owner-scoped read and that `UPDATE`; a bulk revocation, which every security
 * change and a sign-out everywhere make, reads its sessions a chunk at a time
 * and writes one `UPDATE` per session, pending ones included, a principal's
 * after one read of its owner, a tenant's for each principal after reading its
 * tenant, and an identity's that keeps a cutoff after the one conditional
 * `UPDATE` that moves it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(RevocationWriter::class)]
#[CoversClass(SessionRevocations::class)]
#[CoversTrait(EndsSessions::class)]
final class SessionRevocationQueryBudgetTest extends PerformanceContractTestCase
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
     * Signing out a request bound to its session writes the one revocation and
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

        $guard->login($identity, $identity, $session->record);

        self::assertTrue($this->assertQueryBudget(0, 1, static fn (): bool => self::sessionsOf($guard)->signOut()));
    }

    /**
     * Revoking one session of the owner reads it through the owner's relation
     * and writes the one revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingOneSessionIsOneReadAndOneUpdate(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();
        $sessions = $this->sessions();
        $id       = IdentifierCoercion::stringify($session->record->getSessionIdentifier());

        self::assertTrue($this->assertQueryBudget(1, 1, static fn (): bool => $sessions->revokeSession($identity, $id, RevocationReason::REVOKED)));
    }

    /**
     * Revoking three sessions of an identity reads one chunk and writes three
     * revocations.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationIsAReadPerChunkAndAnUpdatePerSession(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();
        $this->signIn();

        $sessions = $this->sessions();

        self::assertSame(3, $this->assertQueryBudget(1, 3, static fn (): int => $sessions->revokeSessions($identity, RevocationReason::REVOKED)));
    }

    /**
     * Revoking a 3D principal's two sessions reads its owner afresh (to know
     * whether it can hold sessions) and one chunk, and writes two revocations.
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

        self::assertSame(2, $this->assertQueryBudget(2, 2, static fn (): int => $sessions->revokePrincipalSessions($membership, RevocationReason::REVOKED)));
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
        yield 'a removed credential' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->credentialRemoved($identity)];
        yield 'a removed factor' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->factorRemoved($identity, 'factor-1')->revoked];
        yield 'reset factors' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->factorReset($identity)];
        yield 'a deactivated identity' => [static fn (SessionService $sessions, Identity $identity): int => $sessions->identityDeactivated($identity)];
    }

    /**
     * A security change of an identity with three sessions costs what a bulk
     * revocation costs: one chunk read and an update per session.
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

        self::assertSame(3, $this->assertQueryBudget(1, 3, static fn (): int => $change($sessions, $identity)));
    }

    /**
     * A changed password that keeps the session it was made from reads the same
     * chunk and leaves that session unwritten.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangedPasswordKeepingItsSessionWritesOneUpdateFewer(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();
        $this->signIn();

        $kept     = $this->signIn()->record;
        $sessions = $this->sessions();

        self::assertSame(2, $this->assertQueryBudget(1, 2, static fn (): int => $sessions->passwordChanged($identity, $kept)));
    }

    /**
     * A deactivated principal costs what revoking its sessions costs: its owner
     * read afresh, one chunk and an update per session.
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

        self::assertSame(2, $this->assertQueryBudget(2, 2, static fn (): int => $sessions->principalDeactivated($membership)));
    }

    /**
     * Rows of `[sessions, reads, writes]`: a tenant policy change over that
     * many sessions of the tenant, each falling short, and its cost.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideTenantSessions(): iterable
    {
        yield 'one session' => [1, 5, 1];
        yield 'three sessions' => [3, 11, 3];
    }

    /**
     * A tenant policy change that every session falls short of reads the keys
     * of the tenant's sessions in one locked chunk, then those sessions again
     * in one locked read, and for each its owner, its principal and its
     * provenance, and writes each revocation: linear in the tenant's sessions.
     *
     * @param  int  $count
     * @param  int  $reads
     * @param  int  $writes
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTenantSessions')]
    public function testATenantPolicyChangeIsLinearInTheTenantsSessions(int $count, int $reads, int $writes): void
    {
        [, , $tenant] = $this->seedMember();

        for ($session = 0; $session < $count; $session++) {
            $this->memberSignIn();
        }

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement(connections: ['conn-a'])));

        $sessions = $this->sessions('members');

        self::assertSame($count, $this->assertQueryBudget($reads, $writes, static fn (): int => $sessions->tenantPolicyChanged($tenant)));
    }

    /**
     * Rows of `[principals, reads, writes]`: a tenant's deactivation over that
     * many principals, each with one session, and its cost.
     *
     * @return iterable<string, array{0: int, 1: int, 2: int}>
     */
    public static function provideTenantPrincipals(): iterable
    {
        yield 'one principal' => [1, 4, 1];
        yield 'three principals' => [3, 10, 3];
    }

    /**
     * A tenant's deactivation reads each principal's tenant, owner and
     * sessions, and writes each session's revocation, then reads the sessions
     * still acting in the tenant in one chunk: three reads and one write for
     * each principal with one session, and one read more.
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
     * Signing out everywhere but the request's own session reads the identity's
     * other sessions in one chunk and revokes them.
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

        $guard->login($identity, $identity, $current->record);

        $sessions = self::sessionsOf($guard);

        self::assertSame(2, $this->assertQueryBudget(1, 2, static fn (): int => $sessions->signOutEverywhere(true)));
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

        self::assertSame(2, $this->assertQueryBudget(1, 3, static fn (): int => $sessions->passwordChanged($identity)));
    }

    /**
     * Signing out everywhere but an access-only request's own token leaves the
     * cutoff where it is, so it costs the bulk revocation alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeepingASessionlessTokenWritesNoCutoff(): void
    {
        $identity = $this->seedCutoffIdentity();

        $this->cutoffSignIn();
        $this->cutoffSignIn();

        $guard = $this->freshGuard('cutoff');

        $guard->login($identity, $identity);

        $sessions = self::sessionsOf($guard);

        self::assertSame(2, $this->assertQueryBudget(1, 2, static fn (): int => $sessions->signOutEverywhere(true)));
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
        $config->set('auth.guards.cutoff', ['driver' => 'jwt', 'provider' => 'cutoff', 'application' => ['methods' => ['password']]]);
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
