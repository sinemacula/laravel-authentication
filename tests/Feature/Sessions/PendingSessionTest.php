<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\TestCase;

/**
 * Feature tests of a pending session's proofs read against a real database: the
 * page a factor package asks for, at the smallest and the largest size a
 * requirement check's subject allows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSession::class)]
final class PendingSessionTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /**
     * Freeze the clocks, create the tables and hold every sign-in for a further
     * factor that nothing meets.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new MeetNoRequirement);
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
     * A page of one proof is the newest alone, and a page of the most a subject
     * allows holds every proof, newest first.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testReadsItsProofsAtTheSmallestAndTheLargestPage(): void
    {
        $identity = $this->seedIdentity();
        $signIn   = $this->sessions()->signIn('password', self::credentials());

        self::assertNotNull($signIn->pending);
        self::assertNotNull($signIn->credential);

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addMinute());

        $pending = $this->sessions()->satisfy($signIn->credential, self::adapterProof($identity, 'api', $signIn->pending->id, Purpose::SIGN_IN))->pending;

        self::assertNotNull($pending);
        self::assertSame([ProofKind::ADDITIONAL_FACTOR], array_column($pending->proofs(limit: 1), 'kind'));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], array_column($pending->proofs(limit: RequirementSubject::MAX_LIMIT), 'kind'));
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
}
