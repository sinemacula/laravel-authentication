<?php

declare(strict_types = 1);

namespace Tests\Integration\Jwt;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\PendingTransitions;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\TestCase;

/**
 * Integration tests of a refresh held to its tenant's authentication policy,
 * and of its compare-and-swaps racing other writes to the session, against a
 * real database: a grace retry is asked the policy as a rotation is; a refresh
 * that loses its rotation, or its return to pending, to a switch of the
 * session's tenant refuses rather than issuing for a context it never judged; a
 * return to pending that loses to a rotation or a revocation applies neither
 * twice, and hands out no pair; a revocation for a connection the tenant now
 * requires never revokes a session a switch moved to another tenant; and a
 * rotation that loses to a return to pending whose deadlines equal its own is
 * told apart by the session's status alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(PendingTransitions::class)]
final class RefreshTokenExchangeTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var string Guard over `ActivatableTenantMember` whose sessions end three minutes after they start. */
    private const string CAPPED = 'capped';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var array<string, \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement> What each tenant's policy requires now, by tenant identifier. */
    private array $requirements = [];

    /**
     * Freeze the clocks, create the tables, and bind a policy that answers with
     * what the test says each tenant requires now.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        $policy = new ScriptedTenantAuthenticationPolicy;

        $policy->answer = fn (TenantPolicyContext $context): TenantRequirement => $this->requirements[self::keyOf($context->tenant)] ?? new TenantRequirement;

        app()->instance(TenantAuthenticationPolicy::class, $policy);
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
     * A refresh token inside the grace window is held to the tenant's policy
     * before its retry is answered, as the current one is: a further factor the
     * session lacks returns it to pending, so no pair is handed out.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryThatFallsShortOfAFactorReturnsTheSessionToPending(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn();

        $this->advance(5);

        self::assertTrue($this->refresh($session->tokens->refreshToken->reveal())->isRefreshed());

        $this->requirements[self::keyOf($tenant)] = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $this->recordEvents([SessionReturnedToPending::class]);

        $retried = $this->refresh($session->tokens->refreshToken->reveal());

        self::assertTrue($retried->isPending());
        self::assertNull($retried->session);
        self::assertCount(1, $this->recorded);
        self::assertSame('pending', DB::table('authentication_sessions')->value('status'));
    }

    /**
     * A refresh token inside the grace window whose tenant now requires a
     * connection the session was not established through revokes the session
     * and is refused as `sso_required`, as the current one would be.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryThatNeedsAnotherConnectionRevokesTheSession(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn();

        $this->advance(5);

        self::assertTrue($this->refresh($session->tokens->refreshToken->reveal())->isRefreshed());

        $this->requirements[self::keyOf($tenant)] = new TenantRequirement('v2', connections: ['conn-a']);

        self::assertSame(FailureReason::SSO_REQUIRED, $this->refresh($session->tokens->refreshToken->reveal())->reason);
        self::assertSame(RevocationReason::TENANT_POLICY_CHANGED->value, DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A refresh that loses its rotation to a switch of the session's tenant,
     * presenting the same token, is refused as `session_tenant_mismatch`
     * instead of handing back a pair for the tenant it was admitted in: the
     * switch stands, and nothing is revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshLosingToASwitchOfTheTenantIsRefused(): void
    {
        [, , $tenant] = $this->seedMember();

        $descendant = $this->below($tenant);
        $session    = $this->signIn();

        $this->advance(5);

        $switched = null;

        $this->beforeTheUpdate('previous_refresh_key', function () use ($session, $descendant, &$switched): void {
            $switched = $this->switchTenant($session->tokens->refreshToken->reveal(), $descendant);
        });

        $refused = $this->refresh($session->tokens->refreshToken->reveal());

        self::assertInstanceOf(SwitchResult::class, $switched);
        self::assertTrue($switched->isSwitched());
        self::assertSame(FailureReason::SESSION_TENANT_MISMATCH, $refused->reason);

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame(self::keyOf($descendant), $row->tenant_id);
        self::assertNull($row->revoked_at);
    }

    /**
     * A refresh that falls short of a factor and loses its return to pending to
     * a switch of the session's tenant, presenting the same token, is refused
     * as `session_tenant_mismatch`: the switch stands, active in the tenant it
     * moved to, and nothing returns to pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnToPendingLosingToASwitchOfTheTenantIsRefused(): void
    {
        [, , $tenant] = $this->seedMember();

        $descendant = $this->below($tenant);
        $session    = $this->signIn();

        $this->advance(5);

        $this->requirements[self::keyOf($tenant)] = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $this->beforeTheUpdate('pending_key', function () use ($session, $descendant): void {
            self::assertTrue($this->switchTenant($session->tokens->refreshToken->reveal(), $descendant)->isSwitched());
        });

        $this->recordEvents([SessionReturnedToPending::class]);

        $refused = $this->refresh($session->tokens->refreshToken->reveal());

        self::assertSame(FailureReason::SESSION_TENANT_MISMATCH, $refused->reason);
        self::assertSame([], $this->recordedClasses());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('active', $row->status);
        self::assertSame(self::keyOf($descendant), $row->tenant_id);
    }

    /**
     * A refresh that falls short of a factor and loses its return to pending to
     * a rotation of the same token is refused as `rotation_conflict` instead of
     * getting the pair the policy refused it: the rotation stands, the session
     * stays active and nothing returns to pending; presented again, the same
     * token is judged afresh and returns the session to pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnToPendingLosingToARotationIsAConflict(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn();

        $this->advance(5);

        $key = self::keyOf($tenant);

        $this->requirements[$key] = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $rotated = null;

        $this->beforeTheUpdate('pending_key', function () use ($session, $key, &$rotated): void {

            $requirement = $this->requirements[$key];

            unset($this->requirements[$key]);

            $rotated = $this->refresh($session->tokens->refreshToken->reveal())->session;

            $this->requirements[$key] = $requirement;
        });

        $this->recordEvents([SessionReturnedToPending::class]);

        $refused = $this->refresh($session->tokens->refreshToken->reveal());

        self::assertInstanceOf(SignedInSession::class, $rotated);
        self::assertSame(FailureReason::ROTATION_CONFLICT, $refused->reason);
        self::assertNull($refused->session);
        self::assertSame([], $this->recordedClasses());

        $row      = DB::table('authentication_sessions')->sole();
        $rotation = self::rotationOf($rotated->tokens->refreshToken->reveal());

        self::assertIsString($rotation);
        self::assertSame('active', $row->status);
        self::assertSame(RefreshTokenHasher::hash($rotation), $row->refresh_key);

        self::assertTrue($this->refresh($session->tokens->refreshToken->reveal())->isPending());
    }

    /**
     * A refresh whose tenant now requires a connection, and whose revocation
     * loses to a switch of the session to a tenant it meets, presenting the
     * same token, leaves the switched session alone: nothing is revoked or
     * reported, the session stays active in the tenant it moved to, and the
     * refresh is refused as `session_tenant_mismatch`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationLosingToASwitchOfTheTenantLeavesTheSessionAlone(): void
    {
        [, , $tenant] = $this->seedMember();

        $descendant = $this->below($tenant);
        $session    = $this->signIn();

        $this->advance(5);

        $this->requirements[self::keyOf($tenant)] = new TenantRequirement('v2', connections: ['conn-a']);

        $switched = null;

        $this->beforeTheUpdate('revoked_reason', function () use ($session, $descendant, &$switched): void {
            $switched = $this->switchTenant($session->tokens->refreshToken->reveal(), $descendant);
        });

        $this->recordEvents([SessionRevoked::class]);

        $refused = $this->refresh($session->tokens->refreshToken->reveal());

        self::assertInstanceOf(SwitchResult::class, $switched);
        self::assertTrue($switched->isSwitched());
        self::assertSame(FailureReason::SESSION_TENANT_MISMATCH, $refused->reason);
        self::assertSame([], $this->recordedClasses());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('active', $row->status);
        self::assertSame(self::keyOf($descendant), $row->tenant_id);
        self::assertNull($row->revoked_at);
        self::assertNotNull($row->refresh_key);
    }

    /**
     * A refresh whose tenant now requires a connection, and whose revocation
     * loses to a refresh of the same token in the same tenant, is a conflict:
     * the retry hands out no pair, nothing is revoked or reported, and the
     * session keeps the competitor's rotation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationLosingToARotationIsAConflict(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn();

        $this->advance(5);

        $key = self::keyOf($tenant);

        $this->requirements[$key] = new TenantRequirement('v2', connections: ['conn-a']);

        $rotated = null;

        $this->beforeTheUpdate('revoked_reason', function () use ($session, $key, &$rotated): void {

            $requirement = $this->requirements[$key];

            unset($this->requirements[$key]);

            $rotated = $this->refresh($session->tokens->refreshToken->reveal())->session;

            $this->requirements[$key] = $requirement;
        });

        $this->recordEvents([SessionRevoked::class]);

        $refused = $this->refresh($session->tokens->refreshToken->reveal());

        self::assertInstanceOf(SignedInSession::class, $rotated);
        self::assertSame(FailureReason::ROTATION_CONFLICT, $refused->reason);
        self::assertNull($refused->session);
        self::assertSame([], $this->recordedClasses());

        $row      = DB::table('authentication_sessions')->sole();
        $rotation = self::rotationOf($rotated->tokens->refreshToken->reveal());

        self::assertIsString($rotation);
        self::assertSame('active', $row->status);
        self::assertNull($row->revoked_at);
        self::assertSame(RefreshTokenHasher::hash($rotation), $row->refresh_key);
    }

    /**
     * A refresh that falls short of a factor and loses its return to pending to
     * a revocation of the session fails as `session_revoked` and leaves the
     * revocation in place, the session never pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnToPendingLosingToARevocationFails(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn();

        $this->advance(5);

        $this->requirements[self::keyOf($tenant)] = new TenantRequirement('v2', new Requirement(new RequirementPart));

        $this->beforeTheUpdate('pending_key', function (): void {
            DB::table('authentication_sessions')->update(['revoked_at' => $this->now, 'revoked_reason' => RevocationReason::REVOKED->value]);
        });

        $this->recordEvents([SessionReturnedToPending::class]);

        self::assertSame(FailureReason::SESSION_REVOKED, $this->refresh($session->tokens->refreshToken->reveal())->reason);
        self::assertSame([], $this->recordedClasses());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('active', $row->status);
        self::assertSame(RevocationReason::REVOKED->value, $row->revoked_reason);
    }

    /**
     * A rotation that loses to a return to pending of the same session, whose
     * pending deadline equals the idle deadline the rotation loaded and would
     * write (the session's absolute cap comes before both its idle lifetime and
     * the pending credential's), is told apart by the session's status alone:
     * the rotation misses and fails as `session_pending`, and the session stays
     * pending with the refresh digest the return kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARotationLosingToAReturnWithEqualDeadlinesIsToldApartByItsStatus(): void
    {
        [, , $tenant] = $this->seedMember();

        $session = $this->signIn(self::CAPPED);
        $loaded  = DB::table('authentication_sessions')->sole();

        $this->advance(5);

        $key = self::keyOf($tenant);

        $this->beforeTheUpdate('previous_refresh_key', function () use ($session, $key): void {

            $this->requirements[$key] = new TenantRequirement('v2', new Requirement(new RequirementPart));

            self::assertTrue($this->refresh($session->tokens->refreshToken->reveal(), self::CAPPED)->isPending());
        });

        $refused = $this->refresh($session->tokens->refreshToken->reveal(), self::CAPPED);

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame($loaded->absolute_expires_at, $loaded->idle_expires_at);
        self::assertSame($loaded->idle_expires_at, $row->idle_expires_at);
        self::assertSame(FailureReason::SESSION_PENDING, $refused->reason);
        self::assertSame('pending', $row->status);
        self::assertSame($loaded->refresh_key, $row->refresh_key);
        self::assertNull($row->revoked_at);
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

        $config->set('auth.guards.' . self::CAPPED, [
            'driver'      => 'jwt',
            'provider'    => 'members',
            'application' => ['methods' => ['password']],
            'jwt'         => ['refresh_absolute_ttl_minutes' => 3],
        ]);
    }

    /**
     * Sign the seeded member in on the guard as its membership, in its own
     * tenant.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(string $guard = self::GUARD): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Refresh with the refresh token on the guard, resolved afresh.
     *
     * @param  string  $refreshToken
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Throwable
     */
    private function refresh(#[\SensitiveParameter] string $refreshToken, string $guard = self::GUARD): RefreshResult
    {
        return self::sessionsOf($this->freshGuard($guard))->refresh($refreshToken);
    }

    /**
     * Switch the session the refresh token proves to the tenant, keeping its
     * principal, on a guard resolved afresh.
     *
     * @param  string  $refreshToken
     * @param  \Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switchTenant(#[\SensitiveParameter] string $refreshToken, ActivatableTenant $tenant): SwitchResult
    {
        return self::sessionsOf($this->freshGuard(self::GUARD))->switchTo($refreshToken, SwitchTarget::tenant(TenantSelection::of($tenant->getKey())));
    }

    /**
     * Create an active tenant below the one given, and bind a tree that lets
     * the tenant's principals act in it.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @return \Tests\Integration\Fixtures\ActivatableTenant
     */
    private function below(ActivatableTenant $tenant): ActivatableTenant
    {
        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);
        $tree       = (new DescendantTenants)->place($descendant->getKey(), $tenant->getKey());

        app()->instance(TenantAccess::class, $tree);
        app()->instance(TenantResolver::class, $tree);

        return $descendant;
    }

    /**
     * Run the callback once, just before the next update of a session that
     * names the column executes, as another request that commits first would.
     *
     * @param  string  $column
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheUpdate(string $column, \Closure $callback): void
    {
        $done = false;

        DB::connection()->beforeExecuting(static function (string $query) use ($column, $callback, &$done): void {

            $statement = strtolower($query);

            if ($done || !str_starts_with($statement, 'update') || !str_contains($statement, $column)) {
                return;
            }

            $done = true;

            $callback();
        });
    }

    /**
     * The rotation id a refresh token carries.
     *
     * @param  string  $refreshToken
     * @return mixed
     */
    private static function rotationOf(#[\SensitiveParameter] string $refreshToken): mixed
    {
        $claims = json_decode(JWT::urlsafeB64Decode(explode('.', $refreshToken)[1]), true);

        self::assertIsArray($claims);

        return $claims[Claims::JWT_ID->value] ?? null;
    }

    /**
     * The tenant's identifier, as a session records it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return string
     */
    private static function keyOf(Tenant $tenant): string
    {
        return IdentifierCoercion::stringify($tenant->getTenantIdentifier()) ?? '';
    }

    /**
     * Move the clocks the given number of seconds on.
     *
     * @param  int  $seconds
     * @return void
     */
    private function advance(int $seconds): void
    {
        $this->freezeAt($this->now->addSeconds($seconds));
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
