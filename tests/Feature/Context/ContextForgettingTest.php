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
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
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

        self::assertTrue(Auth::sessions('api')->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()))->isIssued());

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

        self::assertTrue(Auth::sessions('api')->stepUp($proof)->isIssued());
        self::assertSame($before, $guard->authenticationContext());

        DB::rollBack();

        $rolledBack = $guard->authenticationContext();

        self::assertNotSame($before, $rolledBack);
        self::assertEquals($before, $rolledBack);

        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp($proof)->isIssued());
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

        self::assertTrue(Auth::sessions('api')->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()))->isIssued());

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

        self::assertTrue(Auth::sessions('api')->reauthenticate($signedIn->record, 'password', self::credentials())->isIssued());
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

        self::assertTrue(Auth::sessions('api')->stepUp($proof)->isIssued());
        self::assertTrue($guard->authenticationContext()?->mfa);

        DB::commit();
        DB::rollBack();

        self::assertFalse($guard->authenticationContext()->mfa);

        $guard = $this->bearerGuard($signedIn);

        DB::beginTransaction();
        DB::beginTransaction();

        self::assertTrue(Auth::sessions('api')->stepUp($proof)->isIssued());
        self::assertTrue($guard->authenticationContext()?->mfa);

        DB::rollBack();

        self::assertFalse($guard->authenticationContext()->mfa);

        DB::commit();

        self::assertFalse($guard->authenticationContext()->mfa);
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

        self::assertArrayHasKey(7, config('auth.guards'));
        self::assertTrue(Auth::sessions('api')->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()))->isIssued());
        self::assertTrue($guard->authenticationContext()->mfa);
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

        self::assertTrue(Auth::sessions('api')->reauthenticate($signedIn->record, 'password', self::credentials())->isIssued());
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
        $signedIn = $this->sessions()->signInExternally($this->linkedResult($identity, subject: 'subject-1', authenticatedAt: $this->now))->session;

        self::assertNotNull($signedIn);

        $guard = $this->bearerGuard($signedIn);

        self::assertSame($this->now->getTimestamp(), self::authTimeOf($guard));

        $this->clockAt($this->now->addMinutes(5));

        $through = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $this->now->addMinutes(5));
        $result  = Auth::sessions('api')->reauthenticateExternally($signedIn->record->getKey(), $through);

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

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The `api` guard, the default, on a request bearing the session's access
     * token, resolved afresh and authenticated by it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function bearerGuard(SignedInSession $session): JwtGuard
    {
        app()->instance('request', Request::create('/context', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]));

        Auth::forgetGuards();
        Auth::shouldUse('api');

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertTrue($guard->check());

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
