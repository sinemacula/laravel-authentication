<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Integration tests of a switch whose session row changes between its re-read
 * and its compare-and-swap.
 *
 * Writes run inside the switch's own transaction, as its row lock bars others.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionSwitch::class)]
#[CoversClass(RefreshRotationStore::class)]
final class SessionSwitchTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions, MarksSharedLocks;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and register the route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);
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
     * A switch racing a refresh is a conflict and the refresh stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRacingARefreshIsAConflict(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $refreshed = null;

        $this->beforeTheSwap(function () use ($session, &$refreshed): void {
            $refreshed = self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
                self::bodyToken($session->tokens),
                self::requestClient(),
            )->session?->tokens;
        });

        $this->recordEvents([PrincipalSwitched::class, SessionRevoked::class]);

        $result = $this->switch($session, $second);

        self::assertNotNull($refreshed);
        self::assertSame(FailureReason::ROTATION_CONFLICT, $result->reason);
        self::assertSame([], $this->recordedClasses());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame((string) $first->getKey(), (string) $row->principal_id); // @phpstan-ignore cast.string
        self::assertNull($row->switched_at);
        self::assertNull($row->revoked_at);
    }

    /**
     * A switch racing a revocation fails as `session_revoked`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRacingARevocationFails(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->beforeTheSwap(static function (): void {
            $revoked = ['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked', 'refresh_key' => null, 'previous_refresh_key' => null];

            DB::table('authentication_sessions')->update($revoked);
        });

        self::assertSame(FailureReason::SESSION_REVOKED, $this->switch($session, $second)->reason);
        self::assertSame('revoked', DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertNull(DB::table('authentication_sessions')->value('switched_at'));
    }

    /**
     * Two identical racing switches both succeed and report once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoIdenticalSwitchesBothSucceedAndReportOnce(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $winner = null;

        $this->beforeTheSwap(function () use ($session, $second, &$winner): void {
            $winner = $this->switch($session, $second);
        });

        $this->recordEvents([PrincipalSwitched::class, AuthenticationFailed::class]);

        $loser = $this->switch($session, $second);

        self::assertInstanceOf(SwitchResult::class, $winner);
        self::assertTrue($winner->isSwitched());
        self::assertTrue($loser->isSwitched());
        self::assertTrue($loser->session?->principal->is($second)); // @phpstan-ignore method.notFound
        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
    }

    /**
     * Of two racing switches to different principals, the first stands and the
     * second is a conflict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoSwitchesToDifferentPrincipalsLeaveTheFirst(): void
    {
        [, $second, $member] = $this->seedMemberships();

        $tenant = ActivatableTenant::query()->create(['name' => 'Third', 'is_active' => true]);
        $third  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        $session = $this->signIn();

        $this->advance(5);

        $this->beforeTheSwap(function () use ($session, $second): void {
            self::assertTrue($this->switch($session, $second)->isSwitched());
        });

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->switch($session, $third)->reason);
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
    }

    /**
     * A missed swap without a rotation is a conflict, or `session_unknown` if
     * the session was deleted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwapThatMissesWithoutARotationFails(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->beforeTheSwap(function (): void {
            DB::table('authentication_sessions')->update(['idle_expires_at' => $this->now->addDay()]);
        });

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->switch($session, $second)->reason);

        $this->beforeTheSwap(static function (): void {
            DB::table('authentication_sessions')->delete();
        });

        self::assertSame(FailureReason::SESSION_UNKNOWN, $this->switch($session, $second)->reason);
    }

    /**
     * A swap that misses a changed tenant or policy version is a conflict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwapThatMissesAChangedTenantOrPolicyVersionIsAConflict(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        foreach (['tenant_id' => IdentifierCoercion::stringify($second->tenant_id), 'tenant_policy_version' => 'v2'] as $column => $value) {

            $this->advance(5);

            $this->beforeTheSwap(static function () use ($column, $value): void {
                DB::table('authentication_sessions')->update([$column => $value]);
            });

            self::assertSame(FailureReason::ROTATION_CONFLICT, $this->switch($session, $second)->reason);

            $row = DB::table('authentication_sessions')->sole();

            self::assertSame($value, $row->{$column});
            self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify($row->principal_id));
            self::assertNull($row->switched_at);

            DB::table('authentication_sessions')->update(['tenant_id' => IdentifierCoercion::stringify($first->tenant_id), 'tenant_policy_version' => null]);
        }
    }

    /**
     * A missed swap to the current principal is a conflict, not a retry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwapToTheCurrentPrincipalThatMissesIsAConflict(): void
    {
        [$first] = $this->seedMemberships();

        $session = $this->signIn();

        $this->beforeTheSwap(function (): void {
            DB::table('authentication_sessions')->update(['idle_expires_at' => $this->now->addDay()]);
        });

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->switch($session, $first)->reason);
    }

    /**
     * A lost swap to a move of the session to another identity is refused as
     * `identity_unknown`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostSwapReChecksTheOwner(): void
    {
        [, $second] = $this->seedMemberships();

        [$other] = $this->seedMember('other@example.test');

        $session = $this->signIn();

        $this->advance(5);

        $this->beforeTheSwap(function () use ($session, $second, $other): void {
            self::assertTrue($this->switch($session, $second)->isSwitched());

            DB::table('authentication_sessions')->update(['authenticatable_id' => IdentifierCoercion::stringify($other->getKey())]);
        });

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $this->switch($session, $second)->reason);
    }

    /**
     * A retried switch runs every live check on the target again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARetriedSwitchChecksTheTargetAgain(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        self::assertTrue($this->switch($session, $second)->isSwitched());

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        self::assertSame(FailureReason::TENANT_INACTIVE, $this->switch($session, $second)->reason);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
    }

    /**
     * A lost swap to a refresh with no grace window revokes the session as
     * `rotation_reuse`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostSwapToARefreshWithoutAGraceWindowRevokesTheSession(): void
    {
        config()->set('auth.guards.' . self::GUARD . '.jwt.refresh_grace_seconds', 0);

        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $refreshed = [];

        $this->beforeTheSwap(function () use ($session, &$refreshed): void {
            $refreshed[] = self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
                self::bodyToken($session->tokens),
                self::requestClient(),
            )->session?->tokens;
        });

        $this->assertALostSwapRevokesTheSession($session, $second, $refreshed);
    }

    /**
     * A lost swap to two rotations revokes the session as `rotation_reuse`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostSwapToTwoRotationsRevokesTheSession(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $refreshed = [];

        $this->beforeTheSwap(function () use ($session, &$refreshed): void {

            $refreshed[] = $first = self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
                self::bodyToken($session->tokens),
                self::requestClient(),
            )->session?->tokens;

            self::assertNotNull($first);

            $refreshed[] = self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
                self::bodyToken($first),
                self::requestClient(),
            )->session?->tokens;
        });

        $this->assertALostSwapRevokesTheSession($session, $second, $refreshed);
    }

    /**
     * A return to pending that loses to a refresh is a conflict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnToPendingLosingToARefreshIsAConflict(): void
    {
        [$first, $second] = $this->seedMemberships();

        $policy = new ScriptedTenantAuthenticationPolicy;

        $destination = IdentifierCoercion::stringify($second->tenant_id);

        $policy->answer = static fn (TenantPolicyContext $context): TenantRequirement => IdentifierCoercion::stringify($context->tenant->getTenantIdentifier()) === $destination
            ? new TenantRequirement('v1', new Requirement(new RequirementPart))
            : new TenantRequirement;

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        $session = $this->signIn();

        $this->advance(5);

        $refreshed = null;

        $this->beforeTheReturn(function () use ($session, &$refreshed): void {
            $refreshed = self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
                self::bodyToken($session->tokens),
                self::requestClient(),
            )->session;
        });

        $this->recordEvents([SessionReturnedToPending::class, PrincipalSwitched::class]);

        $result = $this->switch($session, $second);

        self::assertNotNull($refreshed);
        self::assertSame(FailureReason::ROTATION_CONFLICT, $result->reason);
        self::assertSame([], $this->recordedClasses());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('active', $row->status);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify($row->principal_id));
        self::assertNull($row->switched_at);
    }

    /**
     * A grace retry's return to pending that loses to a revocation is a
     * conflict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetrysReturnToPendingLosingToARevocationIsAConflict(): void
    {
        [$first] = $this->seedMemberships();

        $policy = new ScriptedTenantAuthenticationPolicy;

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        $session = $this->signIn();

        $this->advance(5);

        self::assertNotNull(
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );

        $policy->requirement = new TenantRequirement('v1', new Requirement(new RequirementPart));

        $this->beforeTheReturn(function (): void {
            DB::table('authentication_sessions')->update(['revoked_at' => $this->now, 'revoked_reason' => RevocationReason::REVOKED->value]);
        });

        $this->recordEvents([SessionReturnedToPending::class, PrincipalSwitched::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::tenant(TenantSelection::principalDefault()),
            self::requestClient(),
        );

        self::assertSame(FailureReason::ROTATION_CONFLICT, $result->reason);
        self::assertSame([], $this->recordedClasses());

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('active', $row->status);
        self::assertSame(RevocationReason::REVOKED->value, $row->revoked_reason);
        self::assertNull($row->pending_key);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify($row->principal_id));
    }

    /**
     * A switch reads the session's proofs under a shared lock where the engine
     * takes one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchReadsTheSessionsProofsCurrent(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', new Requirement(new RequirementPart))));
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        self::recordProof($session->record, ProofKind::ADDITIONAL_FACTOR, $this->now, ['otp'], new Evaluation(true, false));
        self::markSharedLocks();

        $this->advance(5);

        $locked   = self::takesSharedLocks();
        $results  = [];
        $switched = self::proofReadLocks(function () use ($session, $second, &$results): void {
            $results[] = $this->switch($session, $second);
        });
        $retried = self::proofReadLocks(function () use ($session, $second, &$results): void {
            $results[] = $this->switch($session, $second);
        });

        DB::table('authentication_proofs')->where('kind', ProofKind::ADDITIONAL_FACTOR->value)->update(['voided_at' => $this->now]);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $returned = self::proofReadLocks(function () use ($first, &$results): void {
            $results[] = $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($results[1]->session?->tokens),
                SwitchTarget::principal($first),
                self::requestClient(),
            );
        });

        self::assertSame([true, true, false], array_map(static fn (SwitchResult $result): bool => $result->isSwitched(), $results));
        self::assertTrue($results[2]->isPending());
        self::assertSame([$locked, $locked, $locked], $switched);
        self::assertSame([$locked, $locked, $locked], $retried);
        self::assertSame([$locked, $locked, $locked], $returned);
    }

    /**
     * A switch of a session without a first factor fails loudly and switches
     * nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchOfASessionWithoutAFirstFactorFailsLoudly(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', new Requirement(new RequirementPart))));

        DB::table('authentication_proofs')->delete();

        self::markSharedLocks();

        $this->advance(5);

        $locked = self::takesSharedLocks();
        $failed = null;

        $reads = self::proofReadLocks(function () use ($session, $second, &$failed): void {
            try {
                $this->switch($session, $second);
            } catch (\LogicException $exception) {
                $failed = $exception->getMessage();
            }
        });

        self::assertSame('A session the package wrote always records the proof of its first factor.', $failed);
        self::assertSame([$locked, $locked, $locked], $reads);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
    }

    /**
     * Register the guards.
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
     * Persist a member with its default membership and a second one, each in
     * its own tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMembership, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenantMember}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMemberships(): array
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        return [$first, $second, $member];
    }

    /**
     * Sign the member in as its default membership, named so the sign-in is not
     * held for a choice.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $member  = ActivatableTenantMember::query()->where('email', 'member@example.test')->firstOrFail();
        $context = SignInContext::fromRequest(request(), principal: $member->resolveDefaultPrincipal());
        $session = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Switch the session to the target on a guard resolved afresh.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $target
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switch(SignedInSession $session, ActivatableTenantMembership $target): SwitchResult
    {
        return $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($target),
            self::requestClient(),
        );
    }

    /**
     * Run the switch in a transaction and assert it revoked the session as a
     * replay.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $target
     * @param  list<?\SineMacula\Laravel\Authentication\Jwt\TokenPair>  $refreshed
     * @return void
     *
     * @throws \Throwable
     */
    private function assertALostSwapRevokesTheSession(SignedInSession $session, ActivatableTenantMembership $target, array &$refreshed): void
    {
        $this->recordEvents([PrincipalSwitched::class, SessionRevoked::class]);

        $result = DB::transaction(function () use ($session, $target): SwitchResult {

            $result = $this->switch($session, $target);

            self::assertSame([], $this->recordedClasses());

            return $result;
        });

        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::ROTATION_REUSE, $this->recordedEvent(SessionRevoked::class)->reason);

        $row = DB::table('authentication_sessions')->sole();

        self::assertSame('rotation_reuse', $row->revoked_reason);
        self::assertNotNull($row->revoked_at);
        self::assertNull($row->refresh_key);
        self::assertNull($row->previous_refresh_key);
        self::assertNull($row->switched_at);

        $tokens = array_map(static function (?TokenPair $tokens): TokenPair {

            self::assertNotNull($tokens);

            return $tokens;
        }, $refreshed);

        self::assertNotSame([], $tokens);

        foreach ([$session->tokens, ...$tokens] as $pair) {
            $this->bearer($pair->accessToken->reveal())->assertUnauthorized();
            self::assertNull(
                self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($pair), self::requestClient())->session,
            );
        }
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
    }

    /**
     * Run the callback once, just before the next switch's compare-and-swap.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheSwap(\Closure $callback): void
    {
        $done = false;

        DB::connection()->beforeExecuting(static function (string $query) use ($callback, &$done): void {

            $statement = strtolower($query);

            if ($done || !str_starts_with($statement, 'update') || !str_contains($statement, 'previous_refresh_key')) {
                return;
            }

            $done = true;

            $callback();
        });
    }

    /**
     * Run the callback once, just before the next return of a session to
     * pending.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheReturn(\Closure $callback): void
    {
        $done = false;

        DB::connection()->beforeExecuting(static function (string $query) use ($callback, &$done): void {

            $statement = strtolower($query);

            if ($done || !str_starts_with($statement, 'update') || !str_contains($statement, 'pending_key')) {
                return;
            }

            $done = true;

            $callback();
        });
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
