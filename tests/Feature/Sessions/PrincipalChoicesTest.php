<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalChoiceRequired;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;
use SineMacula\Laravel\Authentication\Sessions\DeviceProof;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoices;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\InvitedTenantAudiencePolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\TestCase;

/**
 * Feature tests of the principal choices on their own: which principals an
 * identity may choose from, a sign-in held for a choice and reported once
 * committed, and finding the live choice a token names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalChoices::class)]
final class PrincipalChoicesTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`. */
    private const string GUARD = 'choosers';

    /** @var list<array<string, string>> The windows of the slots a sign-in took, as a limiter records them. */
    private const array WINDOWS = [['ip' => '1:60']];

    /**
     * Freeze the clock and create the tables.
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

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
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
     * Rows of `[reason, with identity, awaits a choice]`.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 1: bool, 2: bool}>
     */
    public static function provideRefusals(): iterable
    {
        yield 'no principal for a verified identity' => [FailureReason::PRINCIPAL_UNRESOLVED, true, true];
        yield 'no principal and no identity' => [FailureReason::PRINCIPAL_UNRESOLVED, false, false];
        yield 'another reason for a verified identity' => [FailureReason::PRINCIPAL_MISMATCH, true, false];
    }

    /**
     * Only a verified identity that lacks a principal awaits a choice.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  bool  $withIdentity
     * @param  bool  $awaits
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testOnlyAVerifiedIdentityWithoutAPrincipalAwaitsAChoice(FailureReason $reason, bool $withIdentity, bool $awaits): void
    {
        $identity = $withIdentity ? $this->seedMemberWithout() : null;

        self::assertSame($awaits, PrincipalChoices::awaitsChoice(new Refused($reason, $identity)));
    }

    /**
     * The admissible principals are the identity's memberships in active
     * tenants, in order, with no refusal to report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAdmissiblePrincipalsAreTheEligibleOnes(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $closed = ActivatableTenant::query()->create(['name' => 'Closed', 'is_active' => false]);

        ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $closed->getKey()]);

        [$principals, $refusal] = $this->choices($this->freshGuard(self::GUARD))->admissible($member, null);

        self::assertSame([$first->getKey(), $second->getKey()], self::keys($principals));
        self::assertNull($refusal);
    }

    /**
     * With an identifier type, the admissible principals are those the audience
     * policy also admits with it; an identity refused the type has none, and is
     * refused with the policy's reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheAdmissiblePrincipalsWithAnIdentifierTypeAreThoseThePolicyAdmits(): void
    {
        [$member, $own, $invited] = $this->seedChooser();

        $choices = $this->choices($this->freshGuard(self::GUARD));

        app()->instance(AudiencePolicy::class, new InvitedTenantAudiencePolicy(app(AudiencePolicy::class), $invited->tenant_id));

        [$typed, $typedRefusal] = $choices->admissible($member, 'email');

        self::assertSame([$own->getKey()], self::keys($typed));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $typedRefusal);
        self::assertSame([$own->getKey(), $invited->getKey()], self::keys($choices->admissible($member, null)[0]));

        $audience = \Mockery::mock(AudiencePolicy::class);
        $audience->shouldReceive('admitIdentifier')->once()->with(self::GUARD, $member, 'email')->andReturn(FailureReason::IDENTIFIER_UNVERIFIED);
        $audience->shouldReceive('admit')->twice()->with(self::GUARD, $member, \Mockery::type(ChoosingMembership::class), null)->andReturnNull();

        app()->instance(AudiencePolicy::class, $audience);

        self::assertSame([[], FailureReason::IDENTIFIER_UNVERIFIED], $choices->admissible($member, 'email'));
        self::assertSame([$own->getKey(), $invited->getKey()], self::keys($choices->admissible($member, null)[0]));
    }

    /**
     * An identity that is its own principal may choose only the resolver's
     * default, itself; an identity with no `principals()` that is not a
     * principal goes to the resolver too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutPrincipalsHasTheResolversDefault(): void
    {
        $identity = $this->seedIdentity();

        self::assertSame([[$identity], null], $this->choices($this->freshGuard())->admissible($identity, null));

        $this->expectException(UnresolvableIdentityException::class);

        $this->choices($this->freshGuard())->admissible(\Mockery::mock(Identity::class), null);
    }

    /**
     * A sign-in held for a choice stores the choice with the slots it took and
     * answers with the eligible principals; `PrincipalChoiceRequired` waits for
     * the caller's commit, and nothing is bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsOfferedAndReportedOnceCommitted(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $guard = $this->freshGuard(self::GUARD);

        $this->recordEvents([PrincipalChoiceRequired::class]);

        DB::beginTransaction();

        $result = $this->choices($guard)->offerChoice($member, 'password', 'email', SignInContext::fromRequest(app('request')), self::WINDOWS);

        self::assertInstanceOf(SignInResult::class, $result);
        self::assertTrue($result->requiresPrincipal());
        self::assertSame([$first->getKey(), $second->getKey()], self::keys($result->choice->principals ?? []));
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        $pending = PendingSignIn::query()->sole();

        self::assertSame([PrincipalChoiceRequired::class], $this->recordedClasses());
        self::assertSame(PendingSignIn::PRINCIPAL_CHOICE, $pending->purpose);
        self::assertSame(self::WINDOWS, $pending->attempt_windows);
        self::assertSame('email', $pending->identifier_type);
        self::assertTrue($guard->guest());
    }

    /**
     * An identity with no eligible principal is refused as
     * `principal_unresolved`, with no choice stored or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithNoEligiblePrincipalIsRefused(): void
    {
        $member = $this->seedMemberWithout();

        $this->recordEvents([PrincipalChoiceRequired::class]);

        $refused = $this->choices($this->freshGuard(self::GUARD))->offerChoice($member, 'password', null, SignInContext::fromRequest(app('request')), null);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $refused->reason);
        self::assertSame($member, $refused->identity);
        self::assertSame(0, PendingSignIn::query()->count());
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * An identifier type the audience policy refuses every principal to refuses
     * the sign-in with the policy's reason, with no choice stored.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierRefusedEveryPrincipalIsRefusedWithThePolicysReason(): void
    {
        $member  = $this->seedMemberWithout();
        $invited = ActivatableTenant::query()->create(['name' => 'Invited', 'is_active' => true]);

        ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $invited->getKey()]);

        app()->instance(AudiencePolicy::class, new InvitedTenantAudiencePolicy(app(AudiencePolicy::class), $invited->getKey()));

        $refused = $this->choices($this->freshGuard(self::GUARD))->offerChoice($member, 'password', 'email', SignInContext::fromRequest(app('request')), null);

        self::assertInstanceOf(Refused::class, $refused);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused->reason);
        self::assertSame(0, PendingSignIn::query()->count());
    }

    /**
     * A choice whose identity is gone is no live choice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceWhoseIdentityIsGoneIsNotLive(): void
    {
        [$member] = $this->seedChooser();

        $choices = $this->choices($this->freshGuard(self::GUARD));
        $result  = $choices->offerChoice($member, 'password', null, SignInContext::fromRequest(app('request')), null);

        self::assertInstanceOf(SignInResult::class, $result);

        $member->delete();

        self::assertNull($choices->liveChoice($result->choice->token ?? '', CarbonImmutable::now()));
    }

    /**
     * The live choice a token names comes with its secret and its identity,
     * until it is used up; a token that names no choice finds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALiveChoiceIsFoundUntilItIsUsedUp(): void
    {
        [$member] = $this->seedChooser();

        $choices = $this->choices($this->freshGuard(self::GUARD));
        $result  = $choices->offerChoice($member, 'password', null, SignInContext::fromRequest(app('request')), null);

        self::assertInstanceOf(SignInResult::class, $result);

        $token = $result->choice->token ?? '';
        $now   = CarbonImmutable::now();
        $live  = $choices->liveChoice($token, $now);

        self::assertNotNull($live);

        [$pending, $secret, $identity] = $live;

        self::assertSame($member->getKey(), $identity->getAuthIdentifier());
        self::assertNull($choices->liveChoice($token . 'x', $now));
        self::assertTrue(PendingSignIns::delete($pending, $secret, $now));
        self::assertNull($choices->liveChoice($token, $now));
    }

    /**
     * Register the session guards and the guard over choosing members.
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
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password']]]);
    }

    /**
     * The principal choices of the guard, built from the collaborators the
     * session service builds them with.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\PrincipalChoices
     */
    private function choices(JwtGuard $guard): PrincipalChoices
    {
        return new PrincipalChoices(
            $guard->context(),
            new DeviceProof($guard->tokens()),
            new PendingSignIns(app(ConfigRepository::class)),
            new AfterCommit(static fn (): mixed => app('db.transactions')),
            app(),
        );
    }

    /**
     * Persist a member with two memberships, each in its own active tenant.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership, 2: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member = $this->seedMemberWithout();
        $first  = ActivatableTenant::query()->create(['name' => 'First', 'is_active' => true]);
        $second = ActivatableTenant::query()->create(['name' => 'Second', 'is_active' => true]);

        return [
            $member,
            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $first->getKey()]),
            ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $second->getKey()]),
        ];
    }

    /**
     * Persist a member with no memberships.
     *
     * @return \Tests\Integration\Fixtures\ChoosingMember
     */
    private function seedMemberWithout(): ChoosingMember
    {
        return ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
    }

    /**
     * The keys of the principals.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return list<mixed>
     */
    private static function keys(array $principals): array
    {
        return array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $principals);
    }
}
