<?php

declare(strict_types = 1);

namespace Tests\Feature\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeRequests;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\RateLimiting\AccountAttempts;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InteractsWithRateLimits;
use Tests\Fixtures\Freshness\ScriptedFreshness;
use Tests\TestCase;

/**
 * Feature tests for an identifier change under a freshness policy the
 * application bound in place of the package's: the request and its confirmation
 * ask the bound policy, whose requirement decides whether a password is taken
 * and whose answer decides whether a session is fresh, while the package still
 * judges the session itself, before the transaction and on its locked row
 * inside it, where the policy is asked current.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecentAuthentication::class)]
#[CoversClass(ChangeRequests::class)]
#[CoversClass(IdentifierChangeService::class)]
final class ReboundFreshnessPolicyTest extends TestCase
{
    use ChangesIdentifiers, InteractsWithRateLimits;

    /**
     * Start every test from a known moment, with the fakes bound.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->startChanging();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');
    }

    /**
     * Drop the table and release the clock.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->stopChanging();

        parent::tearDown();
    }

    /**
     * The bound policy decides whether a session is fresh: a session that
     * signed in days ago, stale under the configured freshness, is fresh when
     * the policy finds a proof, and one that signed in just now is not when it
     * finds none. It is asked for the requirement up front, then for a proof
     * before the transaction and again, current, inside it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBoundPolicyDecidesWhetherASessionIsFresh(): void
    {
        $identity = self::seedChangeable();
        $policy   = $this->bind(new ScriptedFreshness(null));
        $request  = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session(self::seedSession($identity, 'web', $this->now->subDays(10))));

        self::assertSame(IdentifierChangeRequestStatus::SENT, $request->status);
        self::assertSame(['requirement:web:identifier_change', 'freshProof:identifier_change', 'freshProof:identifier_change (current)'], $policy->asked);

        DB::table('identifier_changes')->delete();

        $this->bind(new ScriptedFreshness(null, false));

        $refused = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session(self::seedSession($identity)));

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $refused->status);
        self::assertSame(0, self::rows('identifier_changes'));
    }

    /**
     * Whatever the bound policy answers, the package judges the session as
     * stored before asking it: a revoked session, one of another guard and one
     * past its deadline prove nothing, and the policy is never asked for their
     * proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotLiveProvesNothingWhateverThePolicySays(): void
    {
        $identity = self::seedChangeable();
        $revoked  = self::seedSession($identity);
        $ended    = self::seedSession($identity);

        DB::table('authentication_sessions')->where('id', $revoked->getKey())->update(['revoked_at' => '2026-04-06 11:59:00']);
        DB::table('authentication_sessions')->where('id', $ended->getKey())->update(['idle_expires_at' => '2026-04-06 12:00:00']);

        foreach ([$revoked, self::seedSession($identity, 'admin'), $ended] as $session) {

            $policy  = $this->bind(new ScriptedFreshness(null));
            $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session($session));

            self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
            self::assertSame(['requirement:web:identifier_change'], $policy->asked);
        }

        self::assertSame([0, 0], [self::rows('identifier_changes'), self::rows('one_time_codes')]);
    }

    /**
     * A revocation that commits after the check before the transaction, and
     * before the session is locked inside it, refuses the request: the locked
     * row is judged, not only the bound policy's answer, so nothing is written
     * or sent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationBeforeTheLockRefusesTheRequest(): void
    {
        $identity = self::seedChangeable();
        $session  = self::seedSession($identity);

        $this->bind(new ScriptedFreshness(null, true, static function (Session $asked): void {
            DB::table('authentication_sessions')->where('id', $asked->getSessionIdentifier())->update(['revoked_at' => '2026-04-06 12:00:00']);
        }));

        $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session($session));

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        self::assertSame([0, 0], [self::rows('identifier_changes'), self::rows('one_time_codes')]);
    }

    /**
     * The bound policy is asked plainly for the check before the transaction
     * and current for the check under the lock, and the current answer decides:
     * a session it finds fresh plainly but not as committed (a proof voided
     * after the first check) refuses the request, with nothing written or sent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCurrentAnswerUnderTheLockDecides(): void
    {
        $identity = self::seedChangeable();
        $policy   = $this->bind(new ScriptedFreshness(null, true, null, false));
        $request  = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session(self::seedSession($identity)));

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $request->status);
        self::assertSame(['requirement:web:identifier_change', 'freshProof:identifier_change', 'freshProof:identifier_change (current)'], $policy->asked);
        self::assertSame([0, 0], [self::rows('identifier_changes'), self::rows('one_time_codes')]);
    }

    /**
     * The bound policy's requirement decides whether a password is taken: one
     * that takes a first-factor reauthentication takes the right password even
     * where the configuration removed the operation, and one that does not
     * refuses it, with nothing counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheBoundPolicysRequirementDecidesWhetherAPasswordIsTaken(): void
    {
        config()->set('authentication.freshness.identifier_change', null);

        $identity = self::seedChangeable();

        $this->bind(new ScriptedFreshness(new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR])));

        $refused = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD));

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $refused->status);
        self::assertSame(0, self::counterHits('sign_in', 'per_account', AccountAttempts::account($identity)));

        $this->bind(new ScriptedFreshness(new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR_REAUTHENTICATION])));

        $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::password(self::PASSWORD));

        self::assertSame(IdentifierChangeRequestStatus::SENT, $request->status);
    }

    /**
     * A confirmation asks the bound policy for the operation's requirement
     * before it makes the change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationAsksTheBoundPolicy(): void
    {
        $identity = self::seedChangeable();

        $this->bind(new ScriptedFreshness(null));

        $request = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session(self::seedSession($identity)));

        self::assertSame(IdentifierChangeRequestStatus::SENT, $request->status);

        $policy = $this->bind(new ScriptedFreshness(null));

        self::assertSame(IdentifierChangeOutcome::CHANGED, $this->changes()->confirmByCode($identity, 'email', self::changeChallenge($identity, 'email'), self::CODE)->outcome);
        self::assertSame(['requirement:web:identifier_change'], $policy->asked);
    }

    /**
     * Register the guards the tests change identifiers through.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureChangeGuards($app->make(ConfigRepository::class));
    }

    /**
     * Bind the policy in place of the package's, as an application would.
     *
     * @param  \Tests\Fixtures\Freshness\ScriptedFreshness  $policy
     * @return \Tests\Fixtures\Freshness\ScriptedFreshness
     */
    private function bind(ScriptedFreshness $policy): ScriptedFreshness
    {
        app()->instance(FreshnessPolicy::class, $policy);

        return $policy;
    }
}
