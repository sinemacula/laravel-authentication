<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\SessionEvidence;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Fixtures\Factors\FirstFactorMeetsRequirements;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\KeyedTenantMember;
use Tests\Integration\Fixtures\KeyedTenantMembership;
use Tests\Integration\Fixtures\MemberRole;
use Tests\Integration\Fixtures\MemberRoleMembership;
use Tests\Integration\Fixtures\RoleMember;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\TestCase;
use Tests\Unit\Stubs\StubSession;

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

    /** @var string Guard over `KeyedTenantMember`, whose memberships name their tenants by an uncast string key. */
    private const string KEYED = 'keyed';

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
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return $this->test->isFactorRequiredFor($context) ? new Requirement(new RequirementPart) : new Requirement;
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
     * `principal_ineligible`; with the one before it left out too (its tenant
     * inactive), none is listed and the reason is the last one's.
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

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        self::assertSame([[], FailureReason::PRINCIPAL_INELIGIBLE], $this->evaluation(self::CHOOSERS)->principals($member));
    }

    /**
     * A row the identity's `principals()` yields that is not a principal (an
     * invitation kept beside its memberships, say) is passed over, and the
     * memberships after it are still listed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARoleThatIsNotAPrincipalIsPassedOver(): void
    {
        Schema::create('member_roles', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('kind');
            $blueprint->timestamps();
        });

        try {
            $member = RoleMember::query()->create(['email' => 'roles@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

            MemberRole::query()->create(['identity_id' => $member->getKey(), 'kind' => 'invitation']);

            $first  = MemberRole::query()->create(['identity_id' => $member->getKey(), 'kind' => 'membership']);
            $second = MemberRole::query()->create(['identity_id' => $member->getKey(), 'kind' => 'membership']);

            [$principals, $refusal] = $this->evaluation()->principals($member);

            self::assertContainsOnlyInstancesOf(MemberRoleMembership::class, $principals);
            self::assertSame([$first->getKey(), $second->getKey()], array_map(static fn (MemberRoleMembership $principal): mixed => $principal->getKey(), $principals));
            self::assertNull($refusal);
        } finally {
            Schema::drop('member_roles');
        }
    }

    /**
     * An identity the resolver finds no default principal for has none to list,
     * and the application access is never asked about one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityTheResolverHasNoPrincipalForListsNone(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $resolver = \Mockery::mock(PrincipalResolver::class);
        $access   = \Mockery::mock(ApplicationAccess::class);

        $resolver->shouldReceive('resolve')->once()->with($identity)->andReturnNull();
        $access->shouldNotReceive('mayUse');

        app()->instance(ApplicationAccess::class, $access);

        $evaluation = new PendingEvaluation($this->freshGuard()->setPrincipalResolver($resolver)->context(), app());

        self::assertSame([[], null], $evaluation->principals($identity));
    }

    /**
     * One principal is found by its identifier exactly when the list holds it:
     * each of the identity's admitted principals is found as the very principal
     * listed, another identity's is not, one whose tenant went inactive or that
     * the application access refuses drops out of both, and with an identifier
     * type the policy refuses none is found.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnePrincipalIsFoundExactlyWhenTheListHoldsIt(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $stranger = ChoosingMember::query()->create(['email' => 'stranger@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $foreign  = ChoosingMembership::query()->create(['identity_id' => $stranger->getKey(), 'tenant_id' => $first->tenant_id]);

        $agrees = function (string $state, ?string $identifierType = null) use ($member, $first, $second, $foreign): void {

            $evaluation = $this->evaluation(self::CHOOSERS);
            $listed     = array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $evaluation->principals($member, $identifierType)[0]);

            foreach ([$first, $second, $foreign] as $membership) {

                $found = $evaluation->principal($member, $membership->getKey(), $identifierType);

                self::assertSame(in_array($membership->getKey(), $listed, true), $found !== null, $state);
                self::assertTrue($found === null || ($found instanceof ChoosingMembership && $found->is($membership)), $state);
            }

            self::assertNull($evaluation->principal($member, 'unknown', $identifierType), $state);
        };

        $agrees('all admitted');

        self::assertNotNull($this->evaluation(self::CHOOSERS)->principal($member, IdentifierCoercion::stringify($first->getKey())));

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        $agrees('the first tenant inactive');

        $refuses = static fn (string $application, mixed $principal): bool => $principal instanceof ChoosingMembership && $principal->is($second);

        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess($refuses));

        $agrees('the second refused');

        self::assertNull($this->evaluation(self::CHOOSERS)->principal($member, $second->getKey()));

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => true]);

        $this->refuseIdentifiers();

        $agrees('the identifier type refused', 'email');

        self::assertNull($this->evaluation(self::CHOOSERS)->principal($member, $first->getKey(), 'email'));
        self::assertNotNull($this->evaluation(self::CHOOSERS)->principal($member, $first->getKey()));
    }

    /**
     * Without an identifier type the identity is not held to one, as the list
     * does not hold it: a policy that refuses every identifier, even none, is
     * asked only when a type is given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAnIdentifierTypeTheIdentityIsNotHeldToOne(): void
    {
        [$member, $first] = $this->seedChooser();

        $evaluation = $this->evaluation(self::CHOOSERS);
        $policy     = \Mockery::mock(ApplicationPolicy::class);

        $policy->shouldReceive('admitIdentifier')->once()->with(self::CHOOSERS, $member, 'email')->andReturn(FailureReason::IDENTIFIER_UNVERIFIED);
        $policy->shouldReceive('admitIdentifier')->with(self::CHOOSERS, $member, null)->never();

        app()->instance(ApplicationPolicy::class, $policy);

        self::assertSame($first->getKey(), $evaluation->principal($member, $first->getKey())?->getPrincipalIdentifier());
        self::assertNull($evaluation->principal($member, $first->getKey(), 'email'));
    }

    /**
     * Two of the identity's principals that share the identifier name no one
     * principal, so neither is found, and neither is asked whether it may use
     * the application; one with an identifier of its own still is.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoPrincipalsSharingTheIdentifierNameNone(): void
    {
        $twin    = \Mockery::mock(Principal::class);
        $other   = \Mockery::mock(Principal::class);
        $unique  = \Mockery::mock(Principal::class);
        $access  = \Mockery::mock(ApplicationAccess::class);
        $query   = \Mockery::mock(EloquentBuilder::class);
        $members = \Mockery::mock(Identity::class, HasPrincipals::class);

        $twin->shouldReceive('getPrincipalIdentifier')->andReturn('shared');
        $other->shouldReceive('getPrincipalIdentifier')->andReturn('shared');
        $unique->shouldReceive('getPrincipalIdentifier')->andReturn('unique');
        $unique->shouldReceive('getTenant')->andReturnNull();
        $query->shouldReceive('useWritePdo')->andReturnSelf();
        $query->shouldReceive('get')->andReturn(new Collection([$twin, 'not a principal', $other, $unique]));
        $members->shouldReceive('principals')->andReturn($query);
        $access->shouldReceive('mayUse')->once()->with('api', $unique)->andReturnTrue();

        app()->instance(ApplicationAccess::class, $access);

        self::assertNull($this->evaluation()->principal($members, 'shared'));
        self::assertSame($unique, $this->evaluation()->principal($members, 'unique'));
    }

    /**
     * An identity that is its own principal is found through the resolver's
     * default, never its hinted path, which an application's resolver may
     * answer differently: only the default principal's own identifier finds it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityThatIsItsOwnPrincipalIsFoundThroughTheResolversDefault(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $resolver = \Mockery::mock(PrincipalResolver::class);

        $resolver->shouldReceive('resolve')->with($identity)->andReturn($identity);
        $resolver->shouldReceive('resolve')->with($identity, \Mockery::any())->never();

        $evaluation = new PendingEvaluation($this->freshGuard()->setPrincipalResolver($resolver)->context(), app());

        self::assertSame($identity, $evaluation->principal($identity, $identity->getKey()));
        self::assertSame($identity, $evaluation->principal($identity, IdentifierCoercion::stringify($identity->getKey())));
        self::assertNull($evaluation->principal($identity, $other->getKey()));

        $identity->is_active = false;

        self::assertNull($evaluation->principal($identity, $identity->getKey()));
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
     * Under Eloquent strict mode, which prevents lazy loading on the principals
     * an identity's `principals()` reads together, the one of three the
     * application admits is selected holding its tenant: its destination is
     * that tenant, and the sign-in completes in it, without a lazy load.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneAdmittedPrincipalOfSeveralSignsInUnderEloquentStrictMode(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $this->seedMembership($member, false);

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        Model::preventLazyLoading();

        try {
            $selection = $this->evaluation(self::CHOOSERS)->selection($member, null);

            self::assertIsArray($selection);
            self::assertInstanceOf(ChoosingMembership::class, $selection[0]);
            self::assertTrue($first->is($selection[0]));

            $destination = $this->evaluation(self::CHOOSERS)->destination($selection[0], null);
            $signedIn    = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'));
        } finally {
            Model::preventLazyLoading(false);
        }

        self::assertInstanceOf(ActivatableTenant::class, $destination);
        self::assertSame($first->tenant_id, $destination->getKey());
        self::assertTrue($signedIn->isSignedIn());
        self::assertSame((string) $first->tenant_id, $signedIn->session?->record->getTenantId());
    }

    /**
     * Under Eloquent strict mode, a membership whose tenant key the database
     * matches but the batched tenant load does not (`'05'` against `5`) still
     * signs in within its tenant: the session records it and the access token
     * carries it, rather than the tenant being taken for none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantTheBatchedLoadMissesStillHoldsTheSignInUnderEloquentStrictMode(): void
    {
        Schema::create('typed_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->timestamps();
        });

        Schema::create('keyed_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('tenant_id')->nullable();
            $blueprint->timestamps();
        });

        try {
            $member = KeyedTenantMember::query()->create(['email' => 'keyed@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
            $tenant = TypedTenant::query()->create();

            KeyedTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => '0' . IdentifierCoercion::stringify($tenant->getKey())]);

            Model::preventLazyLoading();

            try {
                $signedIn = $this->sessions(self::KEYED)->signIn('password', self::credentials('keyed@example.test'));
            } finally {
                Model::preventLazyLoading(false);
            }

            $expected = IdentifierCoercion::stringify($tenant->getKey());
            $claims   = Auth::jwt(self::KEYED)->parse($signedIn->session?->tokens->accessToken->reveal() ?? '', TokenType::ACCESS);

            self::assertTrue($signedIn->isSignedIn());
            self::assertSame($expected, $signedIn->session?->record->getTenantId());
            self::assertSame($expected, $claims['tenant_id'] ?? null);
        } finally {
            Schema::drop('keyed_memberships');
            Schema::drop('typed_tenants');
        }
    }

    /**
     * Under Eloquent strict mode, each of the principals a choice lists, and
     * each the service lists or looks up for a switch screen, answers
     * `getTenant()` without a lazy load, and a switch to one of them and a
     * refresh succeed. The clocks run, as a refresh token's times are checked
     * against the wall clock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSeveralAdmittedPrincipalsHoldTheirTenantsUnderEloquentStrictMode(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        [$member, $first, $second] = $this->seedChooser();

        $third    = $this->seedMembership($member, false);
        $sessions = $this->sessions(self::CHOOSERS);
        $token    = $sessions->start($member, $first, 'password')->session?->tokens->refreshToken?->reveal();

        self::assertIsString($token);

        Model::preventLazyLoading();

        try {
            $pending  = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'))->pending;
            $listed   = $this->sessions(self::CHOOSERS)->principals($member);
            $found    = $this->sessions(self::CHOOSERS)->principal($member, $second->getKey());
            $refused  = $this->sessions(self::CHOOSERS)->principal($member, $third->getKey());
            $switched = $this->sessions(self::CHOOSERS)->switchTo($token, SwitchTarget::principal($second));
            $tenants  = [self::tenantsOf($pending->principals ?? []), self::tenantsOf($listed), self::tenantsOf($found === null ? [] : [$found])];
        } finally {
            Model::preventLazyLoading(false);
        }

        self::assertSame([[$first->tenant_id, $second->tenant_id], [$first->tenant_id, $second->tenant_id], [$second->tenant_id]], $tenants);
        self::assertNull($refused);
        self::assertTrue($switched->isSwitched());
        self::assertSame((string) $second->tenant_id, $switched->session?->record->getTenantId());

        Model::preventLazyLoading();

        try {
            $refreshed = $this->sessions(self::CHOOSERS)->refresh($switched->session?->tokens->refreshToken?->reveal() ?? '');
        } finally {
            Model::preventLazyLoading(false);
        }

        self::assertTrue($refreshed->isRefreshed());
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
     * The identity owes what its factor policy asks of it, asked about the
     * identity, the first factor and the sign-in with no principal, until the
     * requirement check finds the session's proofs meet it: the default check
     * meets nothing, and a check that judges further factors is met only by one
     * the adapter accepted. A requirement that asks for nothing is owed by no
     * one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFactorIsOwedUntilTheCheckFindsItMet(): void
    {
        [$member] = $this->seedMember();

        $session    = $this->signedIn();
        $evaluation = $this->evaluation('members');
        $client     = new ClientContext('203.0.113.9', 'Agent/1.0');
        $first      = PendingEvaluation::firstFactorOf($session);
        $now        = CarbonImmutable::now();

        self::assertTrue($evaluation->owedFactor($member, $first, $client, 'Laptop', 'web', null, null, $now)->isEmpty());

        $this->factorRequired = true;

        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION], $evaluation->owedFactor($member, $first, $client, 'Laptop', 'web', $session, null, $now)->kinds());
        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION], $evaluation->owedFactor($member, $first, $client, 'Laptop', 'web', null, $session, $now)->kinds());

        $context = end($this->asked);

        self::assertInstanceOf(AdditionalFactorContext::class, $context);
        self::assertSame('members', $context->application);
        self::assertSame($member, $context->identity);
        self::assertSame($first, $context->firstFactor);
        self::assertSame($client, $context->client);
        self::assertSame('Laptop', $context->clientName);
        self::assertSame('web', $context->platform);
        self::assertNull($context->provenSession);

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        ProofWriter::record($session, 'members', self::furtherFactor(false));

        self::assertFalse($evaluation->owedFactor($member, $first, $client, null, null, null, $session, $now)->isEmpty());

        ProofWriter::record($session, 'members', self::furtherFactor(true));

        self::assertTrue($evaluation->owedFactor($member, $first, $client, null, null, null, $session, $now)->isEmpty());
    }

    /**
     * At sign-in the check judges the sign-in's own evidence, in memory, with
     * no session: a check that finds the first factor alone meets the
     * requirement leaves nothing owed, and is asked about that first factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAtSignInTheCheckJudgesTheSignInsEvidence(): void
    {
        [$member] = $this->seedMember();

        $this->factorRequired = true;

        $now      = CarbonImmutable::now();
        $evidence = SessionEvidence::of(SignInProof::unattested('password', $now));
        $judging  = new ProofJudgingRequirementCheck;

        app()->instance(RequirementCheck::class, $judging);

        $client = new ClientContext(null, null);

        self::assertFalse($this->evaluation('members')->owedFactor($member, $evidence->firstFactor, $client, null, null, null, null, $now, $evidence)->isEmpty());

        [$subject] = $judging->judged;

        self::assertNull($subject->session);
        self::assertSame($evidence->firstFactor, $subject->firstFactor);
        self::assertSame([$evidence->firstFactor], $subject->proofs());

        app()->instance(RequirementCheck::class, new FirstFactorMeetsRequirements);

        self::assertTrue($this->evaluation('members')->owedFactor($member, $evidence->firstFactor, $client, null, null, null, null, $now, $evidence)->isEmpty());
    }

    /**
     * At sign-in through an external provider, evidence the evidence policy
     * accepted and says meets the identity-level requirement leaves nothing
     * owed, without a further factor; the default evidence policy leaves it
     * owed, as the check finds it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAtSignInAcceptedEvidenceMeetsTheIdentityLevelRequirement(): void
    {
        [$member] = $this->seedMember();

        $this->factorRequired = true;

        $now      = CarbonImmutable::now();
        $accepted = new ExternalEvidence(['otp'], null, $now);
        $evidence = SessionEvidence::of(SignInProof::external('sso', new Provenance('conn-a', evidence: $accepted), $now, new Evaluation(true, false)));
        $client   = new ClientContext(null, null);

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $owed = fn (): Requirement => $this->evaluation('members')->owedFactor($member, $evidence->firstFactor, $client, null, null, null, null, $now, $evidence);

        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION], $owed()->kinds());

        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::ADDITIONAL_VERIFICATION]));

        self::assertTrue($owed()->isEmpty());
    }

    /**
     * On a stored session the policy is asked as its sign-in was: with the
     * first factor, the client it came from, and the name and platform it gave,
     * as the session records them (as text, even from a model that does not
     * cast them), and the session its client proved it holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOnASessionThePolicyIsAskedAsTheSignInWas(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signedIn();
        $proven  = $this->signedIn();

        $session->forceFill(['created_ip' => '198.51.100.7', 'created_user_agent' => 'Agent/2.0', 'client_name' => 'Phone', 'platform' => 'ios'])->save();

        $this->factorRequired = true;

        $owed    = $this->evaluation('members')->owedFactorOn($session, $member, PendingEvaluation::firstFactorOf($session), $proven, CarbonImmutable::now());
        $context = end($this->asked);

        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION], $owed->kinds());
        self::assertInstanceOf(AdditionalFactorContext::class, $context);
        self::assertSame('198.51.100.7', $context->client->ip);
        self::assertSame('Agent/2.0', $context->client->userAgent);
        self::assertSame('Phone', $context->clientName);
        self::assertSame('ios', $context->platform);
        self::assertSame($proven, $context->provenSession);
        self::assertEquals(PendingEvaluation::firstFactorOf($session), $context->firstFactor);
        self::assertSame(ProofKind::FIRST_FACTOR, $context->firstFactor->kind);

        $uncast = (new StubSession)->forceFill(['id' => 'uncast-session', 'client_name' => 42, 'platform' => 7]);

        $this->evaluation('members')->owedFactorOn($uncast, $member, PendingEvaluation::firstFactorOf($session), null, CarbonImmutable::now());

        $context = end($this->asked);

        self::assertInstanceOf(AdditionalFactorContext::class, $context);
        self::assertSame(['42', '7'], [$context->clientName, $context->platform]);
    }

    /**
     * A session that records no first factor is a misconfiguration: it cannot
     * be judged, so reading its first factor fails loudly.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithNoFirstFactorCannotBeJudged(): void
    {
        $this->seedMember();

        $session = $this->signedIn();

        SessionProof::query()->delete();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A session the package wrote always records the proof of its first factor.');

        PendingEvaluation::firstFactorOf($session);
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
     * A session waits on the further factor while any requirement is
     * outstanding, then on the choice when no principal is selected, and on
     * nothing otherwise.
     *
     * @return void
     */
    public function testASessionWaitsOnTheFactorThenTheChoice(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $owed = new Requirement(multifactor: new RequirementPart);

        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], PendingEvaluation::requirements($owed, null));
        self::assertSame([PendingRequirement::MFA], PendingEvaluation::requirements($owed, $principal));
        self::assertSame([PendingRequirement::PRINCIPAL], PendingEvaluation::requirements(new Requirement, null));
        self::assertSame([], PendingEvaluation::requirements(new Requirement, $principal));
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
        $config->set('auth.providers.' . self::KEYED, ['driver' => 'model', 'model' => KeyedTenantMember::class]);
        $config->set('auth.guards.' . self::KEYED, ['driver' => 'jwt', 'provider' => self::KEYED, 'application' => ['methods' => ['password']]]);
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
             * Allow body credentials as the bound policy does.
             *
             * @param  string  $guard
             * @return bool
             */
            #[\Override]
            public function allowsClientSecretPost(string $guard): bool
            {
                return $this->policy->allowsClientSecretPost($guard);
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
     * Persist a membership of the member in a tenant of its own, active or not.
     *
     * @param  \Tests\Integration\Fixtures\ChoosingMember  $member
     * @param  bool  $active
     * @return \Tests\Integration\Fixtures\ChoosingMembership
     */
    private function seedMembership(ChoosingMember $member, bool $active): ChoosingMembership
    {
        $tenant = ActivatableTenant::query()->create(['name' => 'Another', 'is_active' => $active]);

        return ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
    }

    /**
     * The identifier of the tenant each principal acts within.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return list<mixed>
     */
    private static function tenantsOf(array $principals): array
    {
        return array_map(static fn (Principal $principal): mixed => $principal->getTenant()?->getTenantIdentifier(), $principals);
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
