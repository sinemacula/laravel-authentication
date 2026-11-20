<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\ExactMatch;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use SineMacula\Laravel\Authentication\Sessions\SessionSummary;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;
use Tests\Concerns\InteractsWithFoldingCollations;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Integration\Fixtures\NamedIdentity;
use Tests\TestCase;

/**
 * Integration tests of session owners, principals and tenants whose keys a
 * folding collation counts as equal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveSessions::class)]
#[CoversClass(ExactMatch::class)]
#[CoversClass(IdentitySessions::class)]
#[CoversClass(RevocationScope::class)]
#[CoversClass(TenantPolicyChanges::class)]
final class CollationEqualSessionOwnerTest extends TestCase
{
    use InteractsWithFoldingCollations, InteractsWithSessions, MarksSharedLocks;

    /** @var string The frozen time every lookup and revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clocks, create the tables and fold the session's owner,
     * principal and tenant columns; no named identity loads, so a policy change
     * judges every session short.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::parse(self::NOW));
        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();

        Schema::create('named_identities', static function (Blueprint $blueprint): void {
            $blueprint->string('id')->primary();
        });

        self::foldColumns('authentication_sessions', ['authenticatable_type', 'authenticatable_id']);
        self::foldColumns('authentication_sessions', ['principal_type', 'principal_id', 'tenant_id'], true);
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('named_identities');

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * An identity whose key the collation counts as equal to the owner's finds
     * and revokes none of the owner's sessions.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testACollationEqualKeyFindsAndRevokesNoSession(string $folded): void
    {
        $id = $this->insertSession(NamedIdentity::class, 'alice');

        self::assertColumnFolds('authentication_sessions', 'authenticatable_id', $folded);
        self::assertColumnFolds('authentication_sessions', 'principal_id', $folded);

        $this->assertFindsAndRevokesNone(self::namedIdentity($folded), $id);
    }

    /**
     * An identity whose type the collation counts as equal to the owner's finds
     * and revokes none of the owner's sessions.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACollationEqualTypeFindsAndRevokesNoSession(): void
    {
        $id = $this->insertSession(strtolower(NamedIdentity::class), 'alice');

        self::assertColumnFolds('authentication_sessions', 'authenticatable_type', NamedIdentity::class);
        self::assertColumnFolds('authentication_sessions', 'principal_type', NamedIdentity::class);

        $this->assertFindsAndRevokesNone(self::namedIdentity('alice'), $id);
    }

    /**
     * A tenant whose key the collation counts as equal to another's revokes no
     * session acting in that tenant.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testACollationEqualTenantRevokesNoSession(string $folded): void
    {
        $this->insertSession(NamedIdentity::class, 'grace', 'alice');

        self::assertColumnFolds('authentication_sessions', 'tenant_id', $folded);

        self::assertSame(0, Auth::sessions('api')->tenantDeactivated(self::tenant($folded), []));
        self::assertSame(1, $this->liveSessions());
    }

    /**
     * A policy change of a tenant whose key the collation counts as equal to
     * another's neither judges, revokes nor stamps that tenant's sessions.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testACollationEqualTenantPolicyChangeJudgesNoSession(string $folded): void
    {
        $id = $this->insertSession(NamedIdentity::class, 'grace', 'alice');

        self::assertColumnFolds('authentication_sessions', 'tenant_id', $folded);

        $statements = self::statementsDuring(static fn (): int => Auth::sessions('api')->tenantPolicyChanged(self::tenant($folded)));

        self::assertSame([], preg_grep('/named_identities/', $statements));
        self::assertNull(DB::table('authentication_sessions')->where('id', $id)->value('revoked_at'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $id)->value('tenant_policy_version'));
    }

    /**
     * A session that moves to a collation-equal tenant while a policy change
     * judges it is left alone.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testASessionMovedToACollationEqualTenantMeanwhileIsLeftAlone(string $folded): void
    {
        $id = $this->insertSession(NamedIdentity::class, 'grace', 'alice');

        self::assertColumnFolds('authentication_sessions', 'tenant_id', $folded);

        $moving = true;

        DB::listen(static function (QueryExecuted $query) use ($id, $folded, &$moving): void {
            if (!$moving || preg_match('/^select [`"]id[`"] from [`"]authentication_sessions[`"]/i', $query->sql) !== 1) {
                return;
            }

            $moving = false;

            DB::table('authentication_sessions')->where('id', $id)->update(['tenant_id' => $folded]);
        });

        self::assertSame(0, Auth::sessions('api')->tenantPolicyChanged(self::tenant('alice')));
        self::assertNull(DB::table('authentication_sessions')->where('id', $id)->value('revoked_at'));
        self::assertSame($folded, DB::table('authentication_sessions')->where('id', $id)->value('tenant_id'));
    }

    /**
     * The exact owner, principal and tenant list, find and revoke only their
     * own sessions beside a collation-equal owner's.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testTheExactOwnerFindsAndRevokesOnlyItsOwnSessions(string $folded): void
    {
        $own = $this->insertSession(NamedIdentity::class, 'alice', 'alice');

        self::assertColumnFolds('authentication_sessions', 'authenticatable_id', $folded);

        $other    = $this->insertSession(NamedIdentity::class, $folded, $folded);
        $alice    = self::namedIdentity('alice');
        $sessions = Auth::sessions('api');
        $page     = $sessions->sessions($alice);

        self::assertSame(1, $page->total());
        self::assertSame([$own], array_map(static fn (SessionSummary $summary): string => $summary->id, $page->items()));
        self::assertNull($sessions->session($alice, $other));
        self::assertSame($own, $sessions->session($alice, $own)?->id);
        self::assertSame(1, $sessions->revokeSessions($alice, RevocationReason::REVOKED));
        self::assertSame(1, $this->liveSessions());

        $this->insertSession(NamedIdentity::class, 'alice', 'alice');

        self::assertSame(1, $sessions->revokePrincipalSessions($alice, RevocationReason::REVOKED));
        self::assertSame(1, $this->liveSessions());

        $this->insertSession(NamedIdentity::class, 'grace', 'alice');

        self::assertSame(1, $sessions->tenantDeactivated(self::tenant('alice'), []));
        self::assertSame(1, $this->liveSessions());
        self::assertNull(DB::table('authentication_sessions')->where('id', $other)->value('revoked_at'));
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
     * A tenant identified by the key.
     *
     * @param  string  $key
     * @return \SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private static function tenant(string $key): Tenant
    {
        $tenant = \Mockery::mock(Tenant::class);
        $tenant->shouldReceive('getTenantIdentifier')->andReturn($key);

        return $tenant;
    }

    /**
     * Check no lookup finds the session for the identity, no revocation by it
     * ends the session, and the session stays live.
     *
     * @param  \Tests\Integration\Fixtures\NamedIdentity  $identity
     * @param  string  $id
     * @return void
     *
     * @throws \Throwable
     */
    private function assertFindsAndRevokesNone(NamedIdentity $identity, string $id): void
    {
        $sessions = Auth::sessions('api');
        $page     = $sessions->sessions($identity);

        self::assertSame(0, $page->total());
        self::assertSame([], $page->items());
        self::assertNull($sessions->session($identity, $id));
        self::assertNull($sessions->sessionRecord($identity, $id));
        self::assertFalse($sessions->revokeSession($identity, $id, RevocationReason::REVOKED));
        self::assertSame(0, $sessions->revokeSessions($identity, RevocationReason::REVOKED));
        self::assertSame(0, $sessions->revokePrincipalSessions($identity, RevocationReason::REVOKED));
        self::assertSame(1, $this->liveSessions());
    }

    /**
     * Insert a live session the owner holds as its own principal, in the tenant
     * given, and return its key.
     *
     * @param  string  $type
     * @param  string  $key
     * @param  ?string  $tenant
     * @return string
     */
    private function insertSession(string $type, string $key, ?string $tenant = null): string
    {
        $id = (string) Str::uuid7();

        DB::table('authentication_sessions')->insert([
            'id'                   => $id,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $type,
            'authenticatable_id'   => $key,
            'principal_type'       => $type,
            'principal_id'         => $key,
            'tenant_id'            => $tenant,
            'status'               => 'active',
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'refresh_key'          => hash('sha256', 'refresh-' . $id),
            'signed_in_at'         => '2027-01-15 09:00:00',
            'idle_expires_at'      => '2027-02-15 09:00:00',
            'absolute_expires_at'  => '2027-07-15 09:00:00',
        ]);

        return $id;
    }

    /**
     * How many sessions are not revoked.
     *
     * @return int
     */
    private function liveSessions(): int
    {
        return DB::table('authentication_sessions')->whereNull('revoked_at')->count();
    }
}
