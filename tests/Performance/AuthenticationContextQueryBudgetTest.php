<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContextBuilder;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Context\ScriptedContributor;

/**
 * Query-budget and timing contracts for the authentication context of a
 * person's session token: once the guard has authenticated the request, the
 * context costs the one aggregate read of the session's proofs, however many it
 * holds, and nothing when asked again; the session's provenance is read only
 * when a contributor asks for it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBuilder::class)]
#[CoversClass(ContributionSubject::class)]
final class AuthenticationContextQueryBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

    /** @var int Proofs a long-lived session holds in the timing contract. */
    private const int MANY = 200;

    /** @var float Most seconds building the context of a session with many proofs may take. */
    private const float BUILD_CEILING_SECONDS = 0.25;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow($this->now->toImmutable());

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

        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Once the request is authenticated, the first ask reads the session's
     * proofs once, and every later one reads nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionTokensContextIsOneReadAndThenNone(): void
    {
        $this->authenticated($this->signedIn());

        $first = $this->assertQueryBudget(1, 0, static fn (): ?AuthenticationContext => Auth::context());

        self::assertSame($first, $this->assertQueryBudget(0, 0, static fn (): ?AuthenticationContext => Auth::context()));
    }

    /**
     * A contributor that reads only what it is given costs nothing; one that
     * asks for the session's provenance costs one read, once, however often it
     * asks.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProvenanceIsReadOnlyWhenAContributorAsks(): void
    {
        $this->register('audit', static fn (ContributionSubject $subject): array => ['session' => $subject->context->sessionId]);

        $this->authenticated($this->signedIn());

        $this->assertQueryBudget(1, 0, static fn (): ?AuthenticationContext => Auth::context());

        $this->register('sso', static fn (ContributionSubject $subject): array => [
            'connection_id' => $subject->provenance()?->connectionId,
            'link_id'       => $subject->provenance()?->linkId,
        ]);

        $identity = $this->seedIdentity('external@example.test');
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity))->session;

        self::assertNotNull($session);

        $this->authenticated($session);

        $context = $this->assertQueryBudget(2, 0, static fn (): ?AuthenticationContext => Auth::context());

        self::assertSame(['connection_id' => 'connection-7', 'link_id' => 'link-1'], $context?->contributed['sso']);
    }

    /**
     * However many proofs the session holds, its context is one read of them,
     * and quick.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheContextOfASessionWithManyProofsIsOneQuickRead(): void
    {
        $signedIn = $this->signedIn();

        for ($index = 0; $index < self::MANY; $index++) {
            $kind = $index % 2 === 0 ? ProofKind::ADDITIONAL_FACTOR : ProofKind::RECOVERY_CODE;

            self::recordProof($signedIn->record, $kind, $this->now->subSeconds($index), ['otp'], new Evaluation(true, $index % 3 === 0));
        }

        $this->authenticated($signedIn);

        $started = hrtime(true);
        $context = $this->assertQueryBudget(1, 0, static fn (): ?AuthenticationContext => Auth::context());
        $elapsed = (hrtime(true) - $started) / 1e9;

        self::assertTrue($context?->mfa);
        self::assertLessThan(self::BUILD_CEILING_SECONDS, $elapsed);
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
     * Serve a request bearing the session's access token on the `api` guard,
     * the default, and authenticate it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     */
    private function authenticated(SignedInSession $session): void
    {
        $this->bindRequestWithBearer('/context', $session->tokens->accessToken->reveal());

        Auth::forgetGuards();
        Auth::shouldUse('api');

        self::assertTrue(Auth::guard('api')->check());
    }

    /**
     * Register a contributor answering what the script does under the
     * namespace.
     *
     * @param  string  $namespace
     * @param  \Closure(\SineMacula\Laravel\Authentication\Context\ContributionSubject): array<array-key, mixed>  $script
     * @return void
     */
    private function register(string $namespace, \Closure $script): void
    {
        app()->instance('tests.context.' . $namespace, new ScriptedContributor($script));

        app(ContextContributors::class)->register($namespace, 'tests.context.' . $namespace);
    }
}
