<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Feature tests of the gate a sign-in, and a pending session each time it is
 * acted on, passes, one check at a time against a real database: the identity,
 * the method, the principals the application admits and the one selected, the
 * tenant a principal is to act in, a recorded principal and tenant, the
 * identity-level factor, the tenant's policy, and what a session waits on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingEvaluation::class)]
final class PendingEvaluationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, whose identities hold several principals. */
    private const string CHOOSERS = 'choosers';

    /** @var list<\SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext> The contexts the factor policy was asked about. */
    private array $asked = [];

    /** @var bool Whether the factor policy asks for a further factor. */
    private bool $factorRequired = false;

    /**
     * Freeze the clocks, create the tables, and bind a factor policy the test
     * switches.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
        CarbonImmutable::setTestNow(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        app()->instance(AdditionalFactorPolicy::class, new readonly class ($this) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  \Tests\Feature\Sessions\PendingEvaluationTest  $test
             */
            public function __construct(

                /** The test that keeps the contexts and holds the answer. */
                private PendingEvaluationTest $test,
            ) {}

            /**
             * Answer with the test's switch, keeping the context.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return $this->test->isFactorRequiredFor($context);
            }
        });
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

        parent::tearDown();
    }

    /**
     * Keep the context the factor policy was asked about, and answer with the
     * test's switch.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return bool
     */
    public function isFactorRequiredFor(AdditionalFactorContext $context): bool
    {
        $this->asked[] = $context;

        return $this->factorRequired;
    }

    /**
     * The identity is refused in the order sign-in checks it: a machine
     * identity, then an inactive one, then one the application policy refuses
     * with the identifier type the sign-in used; an admitted one is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheIdentityIsRefusedInTheOrderSignInChecksIt(): void
    {
        $active   = $this->seedIdentity();
        $inactive = $this->seedIdentity('off@example.test', false);

        self::assertSame(FailureReason::MACHINE_IDENTITY, $this->evaluation()->identityRefusal(\Mockery::mock(MachineIdentity::class), 'email'));
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->evaluation()->identityRefusal($inactive, 'email'));
        self::assertNull($this->evaluation()->identityRefusal($active, 'email'));

        $this->refuseIdentifiers();

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->evaluation()->identityRefusal($active, 'email'));
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $this->evaluation()->identityRefusal($inactive, 'email'));
    }

    /**
     * The method is the application policy's to allow.
     *
     * @return void
     */
    public function testTheMethodIsTheApplicationPolicysToAllow(): void
    {
        self::assertTrue($this->evaluation()->allowsMethod('password'));
        self::assertFalse($this->evaluation()->allowsMethod('magic-link'));
    }

    /**
     * The principals listed are those the application admits, with the reason
     * the last one left out was refused; with an identifier type the policy
     * refuses, none is listed and its reason is given, while without a type the
     * identity is not held to one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsListedAreThoseTheApplicationAdmits(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        [$principals, $refusal] = $this->evaluation(self::CHOOSERS)->principals($member);

        self::assertSame([$second->getKey()], array_map(static fn (ChoosingMembership $membership): mixed => $membership->getKey(), $principals));
        self::assertSame(FailureReason::TENANT_INACTIVE, $refusal);

        $this->refuseIdentifiers();

        self::assertSame([[], FailureReason::IDENTIFIER_UNVERIFIED], $this->evaluation(self::CHOOSERS)->principals($member, 'email'));
        self::assertCount(1, $this->evaluation(self::CHOOSERS)->principals($member)[0]);
    }

    /**
     * A principal the application access refuses is left out as
     * `principal_ineligible`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalTheAccessRefusesIsLeftOut(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $refuses = static fn (string $application, mixed $principal): bool => $principal instanceof ChoosingMembership && $principal->is($second);

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess($refuses));

        [$principals, $refusal] = $this->evaluation(self::CHOOSERS)->principals($member);

        self::assertSame([$first->getKey()], array_map(static fn (ChoosingMembership $membership): mixed => $membership->getKey(), $principals));
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $refusal);
    }

    /**
     * A selection is the principal named when the identity owns it and the
     * application admits it, else the only one admitted, else none with the
     * principals to choose from; a principal named that is not the identity's
     * is `principal_mismatch`, one refused gives its reason, and an identity
     * left with none the reason the last was refused, or
     * `principal_unresolved`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASelectionIsTheNamedTheOnlyOrNoPrincipal(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $evaluation = $this->evaluation(self::CHOOSERS);
        $stranger   = ChoosingMember::query()->create(['email' => 'stranger@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $foreign    = ChoosingMembership::query()->create(['identity_id' => $stranger->getKey(), 'tenant_id' => $first->tenant_id]);

        self::assertSame([null, [$first->getKey(), $second->getKey()]], self::keysOf($evaluation->selection($member, null)));
        self::assertSame([$first->getKey(), []], self::keysOf($evaluation->selection($member, $first)));
        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $evaluation->selection($member, $foreign));

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        self::assertSame([$second->getKey(), []], self::keysOf($evaluation->selection($member, null)));
        self::assertSame(FailureReason::TENANT_INACTIVE, $evaluation->selection($member, $first));
        self::assertSame(FailureReason::TENANT_INACTIVE, $evaluation->named($member, $first));

        ActivatableTenant::query()->update(['is_active' => false]);

        self::assertSame(FailureReason::TENANT_INACTIVE, $evaluation->selection($member, null));

        $lonely = ChoosingMember::query()->create(['email' => 'lonely@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $evaluation->selection($lonely, null));
    }

    /**
     * The tenant a principal is to act in is its own when no selection is
     * given, and the selection's otherwise: by default a principal in a tenant
     * may act in no other tenant, nor in none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDestinationIsThePrincipalsOwnTenantUnlessOneIsSelected(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $other      = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $evaluation = $this->evaluation('members');

        $own = $evaluation->destination($membership, null);

        self::assertInstanceOf(ActivatableTenant::class, $own);
        self::assertTrue($tenant->is($own));
        self::assertSame(FailureReason::TENANT_INELIGIBLE, $evaluation->destination($membership, TenantSelection::none()));
        self::assertSame(FailureReason::TENANT_INELIGIBLE, $evaluation->destination($membership, TenantSelection::of($other->getKey())));
    }

    /**
     * A recorded principal may still hold its session in the tenant the
     * session records while the application admits it and the tenant is
     * active; otherwise the reason it may not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARecordedPrincipalMustStillHoldTheSessionInItsTenant(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn();

        $recorded = $this->evaluation('members')->recorded($session, $membership);

        self::assertInstanceOf(ActivatableTenant::class, $recorded);
        self::assertTrue($tenant->is($recorded));

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(static fn (): bool => true));

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->evaluation('members')->recorded($session, $membership));

        app()->instance(ApplicationAccess::class, new AdmitAnyPrincipal);

        $session->forceFill(['tenant_id' => 'elsewhere'])->syncOriginal();

        self::assertSame(FailureReason::TENANT_INACTIVE, $this->evaluation('members')->recorded($session, $membership));
    }

    /**
     * The identity owes the further factor its policy asks of it, asked about
     * the identity and the sign-in with no principal, until the session holds
     * an accepted further factor: one the adapter did not accept meets nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorIsOwedUntilTheSessionHoldsAnAcceptedOne(): void
    {
        [$member] = $this->seedMember();

        $session    = $this->signedIn();
        $evaluation = $this->evaluation('members');
        $client     = new ClientContext('203.0.113.9', 'Agent/1.0');

        self::assertFalse($evaluation->owesFactor($member, 'password', $client, 'Laptop', 'web', null, null));

        $this->factorRequired = true;

        self::assertTrue($evaluation->owesFactor($member, 'password', $client, 'Laptop', 'web', $session, null));
        self::assertTrue($evaluation->owesFactor($member, 'password', $client, 'Laptop', 'web', null, $session));

        $context = end($this->asked);

        self::assertInstanceOf(AdditionalFactorContext::class, $context);
        self::assertSame('members', $context->guard);
        self::assertSame($member, $context->identity);
        self::assertSame('password', $context->method);
        self::assertSame($client, $context->client);
        self::assertSame('Laptop', $context->clientName);
        self::assertSame('web', $context->platform);
        self::assertNull($context->provenSession);

        ProofWriter::record($session, 'members', self::furtherFactor(false));

        self::assertTrue($evaluation->owesFactor($member, 'password', $client, null, null, null, $session));

        ProofWriter::record($session, 'members', self::furtherFactor(true));

        self::assertFalse($evaluation->owesFactor($member, 'password', $client, null, null, null, $session));
    }

    /**
     * With no principal selected there is no tenant policy to ask, and nothing
     * falls short; with one, the policy of the tenant it is to act in is asked
     * and judges the evidence given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTenantPolicyIsAskedOnlyForASelectedPrincipal(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $policy = new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', connections: ['conn-a']));

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        $now  = CarbonImmutable::now();
        $none = $this->evaluation('members')->tenantPolicy($member, null, $tenant, null, $now);

        self::assertSame(TenantPolicyStanding::MET, $none->standing);
        self::assertNull($none->version);
        self::assertCount(0, $policy->asked);

        $judged = $this->evaluation('members')->tenantPolicy($member, $membership, $tenant, null, $now, SessionEvidence::of(SignInProof::unattested('password', $now)));

        self::assertSame(TenantPolicyStanding::SSO_REQUIRED, $judged->standing);
        self::assertSame('v1', $judged->version);
        self::assertCount(1, $policy->asked);
    }

    /**
     * A session waits on the further factor when it is owed, then on the choice
     * when no principal is selected, and on nothing otherwise.
     *
     * @return void
     */
    public function testASessionWaitsOnTheFactorThenTheChoice(): void
    {
        $principal = \Mockery::mock(Principal::class);

        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], PendingEvaluation::requirements(true, null));
        self::assertSame([PendingRequirement::MFA], PendingEvaluation::requirements(true, $principal));
        self::assertSame([PendingRequirement::PRINCIPAL], PendingEvaluation::requirements(false, null));
        self::assertSame([], PendingEvaluation::requirements(false, $principal));
    }

    /**
     * Register the session guards and the choosers' guard.
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

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password']]]);
    }

    /**
     * The gate of the guard, on a guard resolved afresh.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation
     */
    private function evaluation(string $guard = 'api'): PendingEvaluation
    {
        return new PendingEvaluation($this->freshGuard($guard)->context(), app());
    }

    /**
     * Bind an application policy that refuses every identifier type as
     * unverified, deciding everything else as the bound one does.
     *
     * @return void
     */
    private function refuseIdentifiers(): void
    {
        app()->instance(ApplicationPolicy::class, new readonly class (app(ApplicationPolicy::class)) implements ApplicationPolicy {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
             */
            public function __construct(

                /** The policy everything but identifiers is decided by. */
                private ApplicationPolicy $policy,
            ) {}

            /**
             * Allow the method as the bound policy does.
             *
             * @param  string  $guard
             * @param  string  $method
             * @return bool
             */
            #[\Override]
            public function allowsMethod(string $guard, string $method): bool
            {
                return $this->policy->allowsMethod($guard, $method);
            }

            /**
             * Refuse every identifier type as unverified.
             *
             * @param  string  $guard
             * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
             * @param  ?string  $identifierType
             * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
             */
            #[\Override]
            public function admitIdentifier(string $guard, Identity $identity, ?string $identifierType): ?FailureReason
            {
                return $identifierType === null ? null : FailureReason::IDENTIFIER_UNVERIFIED;
            }

            /**
             * The lifetimes the bound policy gives the guard.
             *
             * @param  string  $guard
             * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
             */
            #[\Override]
            public function lifetimes(string $guard): TokenLifetimes
            {
                return $this->policy->lifetimes($guard);
            }
        });
    }

    /**
     * Sign the seeded member in with its password and return its session.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function signedIn(): Session
    {
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session?->record;

        self::assertInstanceOf(Session::class, $session);

        return $session;
    }

    /**
     * A chooser with two memberships, each in an active tenant of its own.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership, 2: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member      = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);

            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        return [$member, ...$memberships];
    }

    /**
     * A selection with its principals as their keys.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  array{0: ?\SineMacula\Laravel\Authentication\Contracts\Principal, 1: list<\SineMacula\Laravel\Authentication\Contracts\Principal>}|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $selection
     * @return array{0: mixed, 1: list<mixed>}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function keysOf(array|FailureReason $selection): array
    {
        self::assertIsArray($selection);

        [$principal, $principals] = $selection;

        return [$principal?->getPrincipalIdentifier(), array_map(static fn (Principal $candidate): mixed => $candidate->getPrincipalIdentifier(), $principals)];
    }

    /**
     * A further factor for sign-in, accepted by the adapter or not.
     *
     * @param  bool  $accepted
     * @return \SineMacula\Laravel\Authentication\Proofs\NewProof
     */
    private static function furtherFactor(bool $accepted): NewProof
    {
        return new NewProof(
            ProofKind::ADDITIONAL_FACTOR,
            Purpose::SIGN_IN,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            'factor-1',
            new ObservedProperties,
            new Evaluation($accepted, $accepted),
            ['otp'],
            CarbonImmutable::now(),
        );
    }
}
