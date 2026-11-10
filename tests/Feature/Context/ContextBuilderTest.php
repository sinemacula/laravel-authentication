<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Middleware\TrustProxies;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContextBuilder;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Context\ScriptedContributor;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubBareSession;

/**
 * Feature tests of the authentication context a person's request is built with,
 * over HTTP behind `auth`: every package key from what the guard validated, the
 * session's proofs and the request the trusted proxies resolved, never from the
 * token's claims or input; and each registered contributor's keys under its
 * namespace, loudly refused when they are not plain.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBuilder::class)]
#[CoversClass(AuthenticationContext::class)]
final class ContextBuilderTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and register the routes.
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

        foreach (['api', 'members'] as $guard) {
            Route::middleware('auth:' . $guard)->get("/{$guard}/context", static fn (): array => ['context' => Auth::context()?->toArray()]);
        }
    }

    /**
     * Release the clocks and the trusted proxies, and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        TrustProxies::flushState();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A session token's request is a person's: the identity acting as itself in
     * no tenant, the guard as the application, the session, `pwd` at the
     * sign-in's time and nothing further, an access token as the credential, no
     * scopes, and the client's address.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionTokensContextIsWhatTheGuardValidated(): void
    {
        $signedIn = $this->signedIn();
        $identity = IdentifierCoercion::stringify($signedIn->identity->getAuthIdentifier());

        self::assertSame([
            'subject_type'          => 'person',
            'identity_type'         => IntegrationIdentity::class,
            'identity_id'           => $identity,
            'principal_type'        => IntegrationIdentity::class,
            'principal_id'          => $identity,
            'tenant_type'           => null,
            'tenant_id'             => null,
            'application'           => 'api',
            'session_id'            => IdentifierCoercion::stringify($signedIn->record->getKey()),
            'amr'                   => ['pwd'],
            'auth_time'             => $this->now->getTimestamp(),
            'mfa'                   => false,
            'recovery_code'         => false,
            'multifactor'           => false,
            'seconds_since_step_up' => null,
            'credential'            => 'access_token',
            'scopes'                => null,
            'ip'                    => '198.51.100.4',
        ], $this->contextOf($signedIn->tokens->accessToken->reveal())['authentication']);
    }

    /**
     * A step-up is read from the session's proofs, not from the token the
     * request carries: the token issued before it already reports the further
     * factor, multifactor authentication and the seconds since it was proved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpIsReadFromTheProofsNotTheToken(): void
    {
        $signedIn = $this->signedIn();

        $this->clockAt($this->now->addMinute());

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()), self::requestClient())->isIssued());

        $this->clockAt($this->now->addSeconds(150));

        $context = $this->contextOf($signedIn->tokens->accessToken->reveal())['authentication'];

        self::assertSame(
            [['pwd', 'otp', 'mfa'], $this->now->addMinute()->getTimestamp(), true, false, true, 90],
            [$context['amr'], $context['auth_time'], $context['mfa'], $context['recovery_code'], $context['multifactor'], $context['seconds_since_step_up']],
        );
    }

    /**
     * A recovery code is kept apart from an additional verification: it sets
     * its own key, is no multifactor authentication unless its evaluation said
     * so, and times the step-up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecoveryCodeIsKeptApartFromAnAdditionalVerification(): void
    {
        $signedIn = $this->signedIn();

        $this->clockAt($this->now->addMinute());

        $evaluation = new Evaluation(true, false);
        $proof      = self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey(), kind: ProofKind::RECOVERY_CODE, evaluation: $evaluation, methods: ['kba']);

        self::assertTrue($this->sessions()->stepUp($proof, self::requestClient())->isIssued());

        $context = $this->contextOf($signedIn->tokens->accessToken->reveal())['authentication'];

        self::assertSame(
            [['pwd', 'kba'], false, true, false, 0],
            [$context['amr'], $context['mfa'], $context['recovery_code'], $context['multifactor'], $context['seconds_since_step_up']],
        );
    }

    /**
     * The seconds since the step-up are never negative: a context built by a
     * clock that reads earlier than the proof's time counts none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSecondsSinceTheStepUpAreNeverNegative(): void
    {
        $signedIn = $this->signedIn();

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($signedIn->identity, 'api', $signedIn->record->getKey()), self::requestClient())->isIssued());

        $guard = $this->freshGuard();

        $guard->login($signedIn->identity, $signedIn->principal, $signedIn->record);

        $this->clockAt($this->now->subMinute());

        self::assertSame([true, 0], [$guard->authenticationContext()?->mfa, $guard->authenticationContext()?->secondsSinceStepUp]);
    }

    /**
     * A person's access-only token names no session: its context is the token's
     * identity and principal with an access token as the credential, the scopes
     * `Auth::scopes()` gives, and no proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAccessOnlyTokensContextHoldsNoSessionAndNoProof(): void
    {
        $identity = $this->seedIdentity();
        $token    = Auth::jwt('api')->issueAccessToken($identity, $identity, null, null)->reveal();

        Route::middleware('auth:api')->get('/api/context-and-scopes', static fn (): array => ['context' => Auth::context()?->toArray(), 'scopes' => Auth::scopes()]);

        Auth::forgetGuards();

        $response = $this->withToken($token)->getJson('/api/context-and-scopes')->assertOk();
        $context  = $response->json('context.authentication');

        self::assertIsArray($context);
        self::assertSame([
            'identity_id'           => IdentifierCoercion::stringify($identity->getAuthIdentifier()),
            'session_id'            => null,
            'amr'                   => [],
            'auth_time'             => null,
            'mfa'                   => false,
            'recovery_code'         => false,
            'multifactor'           => false,
            'seconds_since_step_up' => null,
            'credential'            => 'access_token',
            'scopes'                => $response->json('scopes'),
        ], array_diff_key($context, array_flip(['subject_type', 'identity_type', 'principal_type', 'principal_id', 'tenant_type', 'tenant_id', 'application', 'ip'])));
    }

    /**
     * A bound session that is not an Eloquent session records no proofs: its
     * context names the session, holds no proof, and reads nothing to say so.
     *
     * @return void
     */
    public function testASessionThatIsNotAnEloquentSessionHoldsNoProof(): void
    {
        $identity = $this->seedIdentity();
        $session  = new StubBareSession(['id' => 'bare-session-1']);
        $guard    = $this->freshGuard();

        $guard->login($identity, $identity, $session);

        DB::enableQueryLog();
        DB::flushQueryLog();

        $context = $guard->authenticationContext();

        self::assertSame([], DB::getQueryLog());
        self::assertNotNull($context);
        self::assertSame(
            ['bare-session-1', [], null, false, false, false, null],
            [$context->sessionId, $context->amr, $context->authTime, $context->mfa, $context->recoveryCode, $context->multifactor, $context->secondsSinceStepUp],
        );
    }

    /**
     * Rows of `[trusted kinds, mfa, multifactor, amr]`: what the evidence
     * policy trusts an external provider's evidence for, and what an external
     * sign-in's context then says.
     *
     * @return iterable<string, array{0: list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>, 1: bool, 2: bool, 3: list<string>}>
     */
    public static function provideExternalEvidence(): iterable
    {
        $external = FirstFactor::EXTERNAL_PROVIDER_METHOD;

        yield 'multifactor' => [[RequirementKind::MULTIFACTOR], true, true, [$external, 'mfa']];
        yield 'additional verification' => [[RequirementKind::ADDITIONAL_VERIFICATION], true, false, [$external]];
        yield 'phishing resistance' => [[RequirementKind::PHISHING_RESISTANCE], false, false, [$external]];
        yield 'a minimum level' => [[RequirementKind::MINIMUM_LEVEL], false, false, [$external]];
        yield 'nothing' => [[], false, false, [$external]];
    }

    /**
     * An external sign-in counts as an additional verification only when the
     * evidence contract accepted its provider's evidence for one or for
     * multifactor authentication; evidence accepted only for phishing
     * resistance or a level, or not accepted, never does.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>  $trusted
     * @param  bool  $mfa
     * @param  bool  $multifactor
     * @param  list<string>  $amr
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideExternalEvidence')]
    public function testAnExternalSignInIsAnAdditionalVerificationOnlyWhenItsEvidenceWasAcceptedForOne(array $trusted, bool $mfa, bool $multifactor, array $amr): void
    {
        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy($trusted));

        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, evidence: new ExternalEvidence(['hwk', 'pin'], 'phrh', $this->now->subMinute()));
        $session  = $this->sessions()->signInExternally($result, self::requestContext())->session;

        self::assertNotNull($session);

        $context = $this->contextOf($session->tokens->accessToken->reveal())['authentication'];

        self::assertSame(
            [$amr, $mfa, $multifactor, $mfa ? 0 : null],
            [$context['amr'], $context['mfa'], $context['multifactor'], $context['seconds_since_step_up']],
        );
    }

    /**
     * A member's request names the membership it acts as and the tenant it is
     * active in, each by its morph class and identifier.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMembersContextNamesItsPrincipalAndActiveTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($session);

        $context = $this->contextOf($session->tokens->accessToken->reveal(), 'members')['authentication'];

        self::assertSame([ActivatableTenantMembership::class, ActivatableTenant::class, 'members'], [$context['principal_type'], $context['tenant_type'], $context['application']]);
        self::assertSame(
            [IdentifierCoercion::stringify($member->getKey()), IdentifierCoercion::stringify($membership->getKey()), IdentifierCoercion::stringify($tenant->getKey())],
            [$context['identity_id'], $context['principal_id'], $context['tenant_id']],
        );
    }

    /**
     * The address is the one Laravel resolves through the application's trusted
     * proxies: a forwarded address from a trusted proxy, the peer's own from
     * any other.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAddressIsTheOneTheTrustedProxiesResolve(): void
    {
        $token = $this->signedIn()->tokens->accessToken->reveal();

        TrustProxies::at(['10.0.0.1']);

        self::assertSame('192.0.2.44', $this->contextOf($token, peer: '10.0.0.1', forwarded: '192.0.2.44')['authentication']['ip']);
        self::assertSame('10.0.0.2', $this->contextOf($token, peer: '10.0.0.2', forwarded: '192.0.2.44')['authentication']['ip']);
    }

    /**
     * A trusted bind made in the request presented no credential: its context
     * names none, and with no session holds no proof.
     *
     * @return void
     */
    public function testATrustedBindPresentsNoCredential(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard();

        $guard->login($identity, $identity);

        Auth::shouldUse('api');

        $context = Auth::context();

        self::assertNotNull($context);
        self::assertSame(
            [null, null, [], null, false],
            [$context->credential, $context->sessionId, $context->amr, $context->authTime, $context->mfa],
        );
    }

    /**
     * Each registered contributor is asked once, in the order registered, with
     * the package's keys and the live identity, principal, tenant and session,
     * and its keys are added under its namespace.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testContributorsAddTheirKeysUnderTheirNamespaces(): void
    {
        $order = [];

        $sso = new ScriptedContributor(static function (ContributionSubject $subject) use (&$order): array {
            $order[] = 'sso';

            return ['session' => IdentifierCoercion::stringify($subject->session?->getSessionIdentifier()), 'mfa_seen' => $subject->context->mfa];
        });

        $mfa = new ScriptedContributor(static function (ContributionSubject $subject) use (&$order): array {
            $order[] = 'mfa';

            return ['identity' => $subject->identity::class, 'tenant' => $subject->tenant, 'principal_is_identity' => $subject->principal === $subject->identity];
        });

        $this->register(['sso' => $sso, 'mfa' => $mfa]);

        $signedIn = $this->signedIn();
        $context  = $this->contextOf($signedIn->tokens->accessToken->reveal());

        self::assertSame(['sso', 'mfa'], $order);
        self::assertSame(['session' => IdentifierCoercion::stringify($signedIn->record->getKey()), 'mfa_seen' => false], $context['sso']);
        self::assertSame(['identity' => IntegrationIdentity::class, 'tenant' => null, 'principal_is_identity' => true], $context['mfa']);
        self::assertSame([], $sso->asked[0]->context->contributed);
    }

    /**
     * A contributor reads the provider context the adapter gave with the
     * session's provenance and reports what it wants of it under its own
     * namespace; the package's own keys carry nothing of it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContributorReportsTheProviderContextUnderItsOwnNamespace(): void
    {
        $sso = new ScriptedContributor(static function (ContributionSubject $subject): array {
            $context = $subject->provenance()?->providerContext?->toArray() ?? [];

            return ['protocol' => $context['protocol'] ?? null, 'connection_id' => $subject->provenance()?->connectionId];
        });

        $this->register(['sso' => $sso]);

        $identity = $this->seedIdentity();
        $result   = $this->linkedResult($identity, providerContext: new ProviderContext(['protocol' => 'saml-6c1f', 'verified_by' => 'domain-4b7d']));
        $session  = $this->sessions()->signInExternally($result, self::requestContext())->session;

        self::assertNotNull($session);

        $context = $this->contextOf($session->tokens->accessToken->reveal());

        self::assertSame(['protocol' => 'saml-6c1f', 'connection_id' => 'connection-7'], $context['sso']);
        self::assertStringNotContainsString('saml-6c1f', (string) json_encode($context['authentication']));
        self::assertStringNotContainsString('domain-4b7d', (string) json_encode($context));
    }

    /**
     * Rows of `[keys, message]`: keys a contributor must not give, and what the
     * failure says.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function provideBadContributions(): iterable
    {
        yield 'a malformed key' => [['Connection' => 'a'], 'The key [Connection] contributed under [sso]'];
        yield 'a list' => [['a', 'b'], 'The key [0] contributed under [sso]'];
        yield 'an object' => [['tenant' => new \stdClass], 'The value of [sso.tenant] must be null, a scalar or an array of them'];
    }

    /**
     * A contributor's keys that are not plain fail the request loudly, naming
     * its namespace and the key, rather than a context being built without
     * them.
     *
     * @param  array<array-key, mixed>  $keys
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideBadContributions')]
    public function testAContributorsBadKeysFailLoudly(array $keys, string $message): void
    {
        $this->register(['sso' => new ScriptedContributor(static fn (): array => $keys)]);

        $guard = $this->boundGuard();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($message);

        $guard->authenticationContext();
    }

    /**
     * A namespace registered with an abstract that does not resolve to a
     * contributor fails loudly, naming it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnAbstractThatIsNoContributorFailsLoudly(): void
    {
        app()->instance('tests.context.sso', new \stdClass);
        app(ContextContributors::class)->register('sso', 'tests.context.sso');

        $guard = $this->boundGuard();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The context contributor registered under [sso] does not implement ' . AuthenticationContextContributor::class . '.');

        $guard->authenticationContext();
    }

    /**
     * A contributor's exception reaches the caller, and no context is held for
     * the request: asked again, the context is built again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAContributorsExceptionPropagates(): void
    {
        $asked = 0;

        $this->register(['sso' => new ScriptedContributor(static function () use (&$asked): array {
            return ++$asked === 1 ? throw new \RuntimeException('The connection store is unavailable.') : ['connection_id' => null];
        })]);

        $guard = $this->boundGuard();

        try {
            $guard->authenticationContext();
            self::fail('The contributor\'s exception was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The connection store is unavailable.', $exception->getMessage());
        }

        self::assertSame(['connection_id' => null], $guard->authenticationContext()?->contributed['sso']);
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
     * A fresh `api` guard bound to a newly signed-in identity's session.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Throwable
     */
    private function boundGuard(): JwtGuard
    {
        $signedIn = $this->signedIn();
        $guard    = $this->freshGuard();

        $guard->login($signedIn->identity, $signedIn->principal, $signedIn->record);

        return $guard;
    }

    /**
     * Register the contributors, each under its namespace, through the
     * container.
     *
     * @param  array<string, \Tests\Fixtures\Context\ScriptedContributor>  $contributors
     * @return void
     */
    private function register(array $contributors): void
    {
        foreach ($contributors as $namespace => $contributor) {

            app()->instance('tests.context.' . $namespace, $contributor);

            app(ContextContributors::class)->register($namespace, 'tests.context.' . $namespace);
        }
    }

    /**
     * The context the guard's route answers for the token, from the peer
     * address given, forwarded for another when one is given.
     *
     * @param  string  $token
     * @param  string  $guard
     * @param  string  $peer
     * @param  ?string  $forwarded
     * @return array<string, array<string, mixed>>
     */
    private function contextOf(#[\SensitiveParameter] string $token, string $guard = 'api', string $peer = '198.51.100.4', ?string $forwarded = null): array
    {
        Auth::forgetGuards();

        $headers = $forwarded === null ? [] : ['X-Forwarded-For' => $forwarded];

        /** @var \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response> $response */
        $response = $this->withServerVariables(['REMOTE_ADDR' => $peer])->withToken($token)->getJson("/{$guard}/context", $headers);

        /** @var array<string, array<string, mixed>> */
        return $response->assertOk()->json('context');
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
