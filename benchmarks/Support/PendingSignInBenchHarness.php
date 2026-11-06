<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Runtime benchmark fixtures for a sign-in that waits on a further factor: a
 * password sign-in the identity-level factor policy holds pending, then the
 * adapter's proof of the factor satisfying it, which activates the session in
 * place. Every package collaborator either step resolves (the sign-in method,
 * the application policy, the attempt limiter, which writes its counters, the
 * tenant policy and the requirement check) is the package's own, from the
 * container; only the factor policy is bound, to ask every sign-in for a
 * further factor. Passwords are checked with `PlainBenchHasher`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PendingSignInBenchHarness
{
    /** @var string Name of the guard signed in with a password. */
    private const string GUARD = 'api';

    /** @var string Shared benchmark password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Email address of the identity that signs in. */
    private const string EMAIL = 'bench-pending@example.test';

    /** @var \Illuminate\Foundation\Application */
    private Application $app;

    /** @var \SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver */
    private DefaultPrincipalResolver $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher */
    private Dispatcher $events;

    /** @var \Illuminate\Support\Timebox */
    private Timebox $timebox;

    /**
     * Seed the identity, ask every sign-in for a further factor that a stored
     * accepted factor meets, and check that the path reaches the outcome it
     * measures.
     *
     * @throws \LogicException
     */
    public function __construct()
    {
        $now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow(CarbonImmutable::instance($now));
        JWT::$timestamp = $now->getTimestamp();

        $this->app = PackageBenchApplication::create([
            self::GUARD => ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]],
        ]);

        $this->app->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Ask every sign-in for a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart);
            }
        });
        $this->app->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $this->resolver = new DefaultPrincipalResolver;
        $this->events   = $this->app->make('events');
        $this->timebox  = new Timebox;

        BenchSchema::ensureIdentityTable('integration_identities');
        BenchSchema::ensureSessionTable();
        BenchSchema::ensureProofTables();
        BenchSchema::ensureRateLimitTable();

        $identity            = new IntegrationIdentity;
        $identity->email     = self::EMAIL;
        $identity->password  = $this->app->make('hash')->make(self::PASSWORD);
        $identity->is_active = true;
        $identity->save();

        BenchOutcome::assert('sign-in to pending to active', $this->signInToPendingToActive()->isSignedIn());
    }

    /**
     * Benchmark a password sign-in written pending, then satisfied by the
     * factor's proof.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function runSignInToPendingToActive(): void
    {
        $this->signInToPendingToActive();
    }

    /**
     * Sign the identity in, which the factor policy holds pending, and satisfy
     * the factor with an accepted proof bound to the pending session, each on a
     * fresh guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \LogicException
     */
    private function signInToPendingToActive(): SignInResult
    {
        $result     = $this->sessions()->signIn('password', ['email' => self::EMAIL, 'password' => self::PASSWORD]);
        $pending    = $result->pending;
        $credential = $result->credential?->reveal();

        if ($pending === null || $credential === null) {
            throw new \LogicException('The pending sign-in benchmark does not reach the outcome it measures; fix its fixtures before timing it.');
        }

        $proof = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            'bench-factor',
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($pending->identity, self::GUARD, $pending->id, Purpose::SIGN_IN),
        );

        return $this->sessions()->satisfy($credential, $proof, ClientContext::fromRequest(BenchRequest::client()));
    }

    /**
     * The session service of a fresh `jwt` guard over the identities, serving a
     * sign-in request from the benchmark's client, built as the auth manager
     * builds one.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function sessions(): SessionService
    {
        $provider = new ModelProvider($this->app->make('hash'), IntegrationIdentity::class);
        $tokens   = $this->app->make(JwtTokenServiceFactory::class)->forGuard(self::GUARD);

        $guard = new JwtGuard(
            self::GUARD,
            $provider,
            $this->resolver,
            $this->events,
            BenchRequest::client()->duplicate(server: ['REQUEST_URI' => '/bench/sign-in', 'REQUEST_METHOD' => Request::METHOD_POST]),
            $this->timebox,
            $tokens,
            static fn (GuardContext $context): SessionRevocations => new SessionRevocations(
                $context,
                new RevocationWriter(BenchDatabase::connectionResolver(), static fn (): null => null),
                Container::getInstance(),
            ),
            BenchRequest::refreshTransport(...),
        );

        return new SessionService($guard->context(), $guard, $tokens, Container::getInstance(), BenchDatabase::connectionResolver(), static fn (): null => null);
    }
}
