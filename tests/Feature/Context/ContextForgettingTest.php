<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\ContextForgetting;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\TestCase;

/**
 * Feature tests of forgetting the authentication context a guard holds when the
 * bound session's proofs change in the request: a step-up, a reauthentication
 * with the first factor and one at the external provider each have every
 * resolved guard bound to the session build it again once the proof commits,
 * never before, and once it rolls back, so a context built inside the
 * transaction never outlives a proof that did not commit; no guard is created
 * to do so.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextForgetting::class)]
#[CoversClass(ProofIssuance::class)]
final class ContextForgettingTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $this->clockAt($this->now);
        $this->createSessionTables();
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
     * A step-up in the request the session's token authenticated makes the rest
     * of the request's context hold the further factor; a guard of another name
     * the request never resolved is not created for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpIsSeenByTheRestOfTheRequest(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);
        $before   = Auth::context();

        self::assertFalse($before?->mfa);

        $this->clockAt($this->now->addMinute());

        self::assertTrue(Auth::sessions('api')->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()), self::requestClient())->isIssued());

        $after = Auth::context();

        self::assertNotSame($before, $after);
        self::assertSame([true, $this->now->addMinute()->getTimestamp()], [$after?->mfa, $after?->authTime?->getTimestamp()]);
        self::assertSame($after, $guard->authenticationContext());
        self::assertNull(Auth::resolvedGuard('admin'));
    }

    /**
     * Inside a caller's transaction a context held from before the step-up is
     * kept until the step-up commits; a step-up rolled back has it built again,
     * from the proofs as they stand.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAHeldContextIsKeptUntilTheProofCommits(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);
        $before   = $guard->authenticationContext();
        $proof    = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey());

        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp($proof, self::requestClient())->isIssued());
        self::assertSame($before, $guard->authenticationContext());

        DB::rollBack();

        $rolledBack = $guard->authenticationContext();

        self::assertNotSame($before, $rolledBack);
        self::assertEquals($before, $rolledBack);

        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp($proof, self::requestClient())->isIssued());
        self::assertSame($rolledBack, $guard->authenticationContext());

        DB::commit();

        self::assertTrue($guard->authenticationContext()?->mfa);
    }

    /**
     * A context first built inside a caller's transaction after a step-up in it
     * holds the uncommitted further factor; once the transaction rolls back the
     * guard forgets it, so the rest of the request holds none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContextBuiltInsideARolledBackStepUpIsForgotten(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);

        $this->clockAt($this->now->addMinute());

        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()), self::requestClient())->isIssued());

        $inside = Auth::context();

        self::assertSame([true, 0, $this->now->addMinute()->getTimestamp()], [$inside?->mfa, $inside?->secondsSinceStepUp, $inside?->authTime?->getTimestamp()]);

        DB::rollBack();

        $after = Auth::context();

        self::assertSame([false, null, $this->now->getTimestamp()], [$after?->mfa, $after?->secondsSinceStepUp, $after?->authTime?->getTimestamp()]);
        self::assertSame($after, $guard->authenticationContext());
    }

    /**
     * A context first built inside a caller's transaction after a
     * reauthentication in it holds the uncommitted authentication time; once
     * the transaction rolls back the guard forgets it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContextBuiltInsideARolledBackReauthenticationIsForgotten(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);

        $this->clockAt($this->now->addMinutes(5));

        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->reauthenticate($signedIn->record, 'password', self::credentials(), self::requestClient())->isIssued());
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), self::authTimeOf($guard));

        DB::rollBack();

        self::assertSame($this->now->getTimestamp(), self::authTimeOf($guard));
    }

    /**
     * A step-up in a nested transaction that commits into the outer one is
     * forgotten when the outer one rolls back, and one whose nested transaction
     * rolls back is forgotten at once, the outer one going on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContextBuiltInsideANestedTransactionIsForgottenWhicheverRollsBack(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);
        $proof    = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey());

        DB::beginTransaction();
        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp($proof, self::requestClient())->isIssued());
        self::assertTrue($guard->authenticationContext()?->mfa);

        DB::commit();
        DB::rollBack();

        self::assertFalse($guard->authenticationContext()->mfa);

        $guard = $this->bearerGuard($signedIn);

        DB::beginTransaction();
        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp($proof, self::requestClient())->isIssued());
        self::assertTrue($guard->authenticationContext()?->mfa);

        DB::rollBack();

        self::assertFalse($guard->authenticationContext()->mfa);

        DB::commit();

        self::assertFalse($guard->authenticationContext()->mfa);
    }

    /**
     * Every resolved guard bound to the session forgets the context it holds,
     * once the proof rolls back and once it commits; a guard bound to another
     * session keeps its own, and a guard the request never resolved is not
     * created to forget.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryResolvedGuardBoundToTheSessionForgetsItsContext(): void
    {
        $signedIn = $this->signedIn();
        $another  = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($another);

        config()->set('auth.guards.elsewhere', config('auth.guards.api'));

        $api       = $this->bearerGuard($signedIn);
        $admin     = self::boundGuard('admin', $signedIn);
        $elsewhere = self::boundGuard('elsewhere', $another);
        $held      = [$api->authenticationContext(), $admin->authenticationContext(), $elsewhere->authenticationContext()];
        $proof     = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey());

        self::assertSame([false, false, false], [$held[0]?->mfa, $held[1]?->mfa, $held[2]?->mfa]);

        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp($proof, self::requestClient())->isIssued());
        self::assertSame($held, [$api->authenticationContext(), $admin->authenticationContext(), $elsewhere->authenticationContext()]);

        DB::rollBack();

        $rolledBack = [$api->authenticationContext(), $admin->authenticationContext()];

        self::assertNotSame($held[0], $rolledBack[0]);
        self::assertNotSame($held[1], $rolledBack[1]);
        self::assertEquals([$held[0], $held[1]], $rolledBack);
        self::assertSame($held[2], $elsewhere->authenticationContext());

        self::assertTrue(Auth::sessions('api')->stepUp($proof, self::requestClient())->isIssued());
        self::assertSame([true, true], [$api->authenticationContext()?->mfa, $admin->authenticationContext()?->mfa]);
        self::assertSame(['api', 'admin'], [$api->authenticationContext()?->application, $admin->authenticationContext()?->application]);
        self::assertSame($held[2], $elsewhere->authenticationContext());
        self::assertNull(Auth::resolvedGuard('members'));
    }

    /**
     * A tenant policy that reads the context once an external
     * reauthentication's proof is recorded, and then refuses it or throws,
     * leaves no context built from that proof: the proof rolls back and the
     * context is built again from the proofs as they stand, inside a caller's
     * transaction too, which goes on.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContextATenantPolicyBuiltFromARefusedProofIsForgotten(): void
    {
        [$member, $membership] = $this->seedMember();

        $result   = $this->linkedResult($member, subject: 'subject-1', authenticatedAt: $this->now);
        $signedIn = $this->sessions('members')->signInExternally($result, self::asPrincipal($membership))->session;

        self::assertNotNull($signedIn);

        $guard  = $this->bearerGuard($signedIn, 'members');
        $policy = new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v2', new Requirement(multifactor: new RequirementPart)));
        $seen   = [];

        $policy->answer = static function () use ($guard, $policy, &$seen): TenantRequirement {
            $seen[] = self::authTimeOf($guard);

            return $policy->requirement;
        };

        $this->app?->instance(TenantAuthenticationPolicy::class, $policy);
        $this->clockAt($this->now->addMinutes(5));

        $through        = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now->addMinutes(5));
        $reauthenticate = static fn (): AccessTokenResult => Auth::sessions('members')->reauthenticateExternally($signedIn->record->getKey(), $through, self::requestClient());
        $thrown         = static function () use ($reauthenticate): string {
            try {
                $reauthenticate();
            } catch (\RuntimeException $exception) {
                return $exception->getMessage();
            }

            return 'nothing thrown';
        };

        $restored = static function () use ($guard, $signedIn): array {
            $restored = [DB::transactionLevel(), self::authTimeOf($guard)];

            $guard->forgetAuthenticationContext($signedIn->record);

            return $restored;
        };

        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $reauthenticate()->reason);
        self::assertSame([0, $this->now->getTimestamp()], $restored());

        DB::beginTransaction();

        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $reauthenticate()->reason);
        self::assertSame([1, $this->now->getTimestamp()], $restored());

        DB::commit();

        $policy->answer = static function () use ($guard, &$seen): never {
            $seen[] = self::authTimeOf($guard);

            throw new \RuntimeException('The tenant policy is unavailable.');
        };

        self::assertSame('The tenant policy is unavailable.', $thrown());
        self::assertSame([0, $this->now->getTimestamp()], $restored());

        DB::beginTransaction();

        self::assertSame('The tenant policy is unavailable.', $thrown());
        self::assertSame([1, $this->now->getTimestamp()], $restored());

        DB::rollBack();

        self::assertSame(array_fill(0, 4, $this->now->addMinutes(5)->getTimestamp()), $seen);
        self::assertSame(0, SessionProof::query()->where('kind', 'external_reauthentication')->count());
        self::assertSame($this->now->getTimestamp(), self::authTimeOf($guard));
    }

    /**
     * A guard configured under a numeric name is asked as every other is: the
     * forgetting reaches the bound guard however the configuration keys them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardConfiguredUnderANumericNameDoesNotStopTheForgetting(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);

        self::assertFalse($guard->authenticationContext()?->mfa);

        config()->set('auth.guards.7', config('auth.guards.api'));

        self::assertArrayHasKey(7, config()->array('auth.guards'));
        self::assertTrue(Auth::sessions('api')->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()), self::requestClient())->isIssued());
        self::assertTrue($guard->authenticationContext()->mfa);
    }

    /**
     * Forgetting now drops the held context at once, inside a transaction that
     * has not settled, so the next ask builds it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testForgettingNowDropsTheHeldContextAtOnce(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);
        $held     = $guard->authenticationContext();

        DB::beginTransaction();

        ContextForgetting::now($signedIn->record);

        $rebuilt = $guard->authenticationContext();

        DB::rollBack();

        self::assertNotSame($held, $rebuilt);
        self::assertEquals($held, $rebuilt);
    }

    /**
     * A reauthentication with the first factor moves the context's
     * authentication time for the rest of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReauthenticationMovesTheContextsAuthenticationTime(): void
    {
        $signedIn = $this->signedIn();
        $guard    = $this->bearerGuard($signedIn);

        self::assertSame($this->now->getTimestamp(), self::authTimeOf($guard));

        $this->clockAt($this->now->addMinutes(5));

        self::assertTrue(Auth::sessions('api')->reauthenticate($signedIn->record, 'password', self::credentials(), self::requestClient())->isIssued());
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), self::authTimeOf($guard));
    }

    /**
     * A reauthentication at the external provider moves the context's
     * authentication time for the rest of the request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalReauthenticationMovesTheContextsAuthenticationTime(): void
    {
        $identity = $this->seedIdentity();
        $signedIn = $this->sessions()->signInExternally($this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->now), self::requestContext())->session;

        self::assertNotNull($signedIn);

        $guard = $this->bearerGuard($signedIn);

        self::assertSame($this->now->getTimestamp(), self::authTimeOf($guard));

        $this->clockAt($this->now->addMinutes(5));

        $through = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now->addMinutes(5));
        $result  = Auth::sessions('api')->reauthenticateExternally($signedIn->record->getKey(), $through, self::requestClient());

        self::assertTrue($result->isIssued());
        self::assertSame($this->now->addMinutes(5)->getTimestamp(), self::authTimeOf($guard));
    }

    /**
     * Register the guards and providers.
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
     * A session the identity signed in to with its password now.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The named guard, made the default, on a request bearing the session's
     * access token, resolved afresh and authenticated by it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearerGuard(SignedInSession $session, string $name = 'api'): JwtGuard
    {
        app()->instance('request', Request::create('/context', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]));

        Auth::forgetGuards();
        Auth::shouldUse($name);

        $guard = app('auth')->guard($name);

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertTrue($guard->check());

        return $guard;
    }

    /**
     * The named guard, resolved for the request, with the session's identity
     * bound to it as its own principal.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private static function boundGuard(string $name, SignedInSession $session): JwtGuard
    {
        $guard = app('auth')->guard($name);

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->login($session->identity, $session->principal, $session->record);

        return $guard;
    }

    /**
     * When the context the guard holds says the session last authenticated, in
     * Unix seconds.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return ?int
     */
    private static function authTimeOf(JwtGuard $guard): ?int
    {
        return $guard->authenticationContext()?->authTime?->getTimestamp();
    }

    /**
     * Move the clocks to the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }
}
