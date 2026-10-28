<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalChoiceRequired;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ChoosesPrincipals;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\PrincipalChoice;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\InvitedTenantAudiencePolicy;
use Tests\Fixtures\Sessions\RecordingAttemptLimiter;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\VerifiableChoosingMember;
use Tests\TestCase;

/**
 * Feature tests of the principal choice: a sign-in that names no principal, for
 * an identity whose resolver has no default, waits for the identity to choose
 * one of the principals it may sign in as, and `choose()` continues it through
 * the same checks as any sign-in, over HTTP and through the session service.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(PendingSignIns::class)]
#[CoversClass(PrincipalChoice::class)]
#[CoversClass(PrincipalChoiceRequired::class)]
#[CoversClass(SignInResult::class)]
#[CoversTrait(ChoosesPrincipals::class)]
final class ChoosesPrincipalsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`. */
    private const string GUARD = 'choosers';

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

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();

        Route::post('/sign-in', static function (Request $request): array {

            $result = Auth::sessions(self::GUARD)->signIn('password', ['email' => $request->string('email')->toString(), 'password' => $request->string('password')->toString()]);

            return [
                'status'     => $result->status->value,
                'choice'     => $result->choice?->token,
                'principals' => array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $result->choice->principals ?? []),
            ];
        });

        Route::post('/choose', static function (Request $request): array {

            $principal = ChoosingMembership::query()->findOrFail($request->integer('membership'));
            $result    = Auth::sessions(self::GUARD)->choose($request->string('choice')->toString(), $principal);

            return [
                'status' => $result->status->value,
                'reason' => $result->reason?->value,
                'access' => $result->session?->tokens->accessToken,
            ];
        });

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);
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
     * Over HTTP, a password sign-in that names no principal answers with a
     * choice of the principals the identity may sign in as, and choosing one
     * signs in as it; the choice cannot be used again.
     *
     * @return void
     */
    public function testAChoiceIsOfferedAndMadeOverHttp(): void
    {
        [, $first, $second] = $this->seedChooser();

        $offered = $this->postJson('/sign-in', self::credentials('chooser@example.test'))->assertOk();

        $offered->assertJson(['status' => 'principal_required', 'principals' => [$first->getKey(), $second->getKey()]]);

        $token  = $offered->json('choice');
        $chosen = $this->postJson('/choose', ['choice' => $token, 'membership' => $second->getKey()])->assertOk();

        $chosen->assertJson(['status' => 'signed_in', 'reason' => null]);

        Auth::forgetGuards();

        $access = $chosen->json('access');

        self::assertIsString($access);

        $this->withHeaders(['Authorization' => 'Bearer ' . $access])->getJson('/me')->assertOk()->assertExactJson(['principal' => $second->getKey()]);

        $this->postJson('/choose', ['choice' => $token, 'membership' => $second->getKey()])->assertOk()->assertJson(['status' => 'failed', 'reason' => 'pending_invalid']);
    }

    /**
     * A sign-in held for a choice starts no session, stores a pending choice
     * that records no principal, keeps its attempt-limit slots, and reports
     * `PrincipalChoiceRequired` with the identity and method but no principal;
     * the choice lists only the principals in active tenants.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInWithoutAPrincipalWaitsForAChoice(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $inactive = ActivatableTenant::query()->create(['name' => 'Closed', 'is_active' => false]);

        ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $inactive->getKey()]);

        $this->recordEvents([PrincipalChoiceRequired::class, SignedIn::class, Login::class, AuthenticationFailed::class]);

        $result = $this->sessions(self::GUARD)->signIn('password', self::credentials('chooser@example.test'));

        self::assertTrue($result->requiresPrincipal());
        self::assertFalse($result->isSignedIn());
        self::assertFalse($result->isFailed());
        self::assertNull($result->session);

        $choice = $result->choice;

        self::assertInstanceOf(PrincipalChoice::class, $choice);
        self::assertSame(self::GUARD, $choice->guard);
        self::assertSame('password', $choice->method);
        self::assertSame($member->getKey(), $choice->identity->getAuthIdentifier());
        self::assertSame([$first->getKey(), $second->getKey()], self::keys($choice->principals));
        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $choice->expiresAt->getTimestamp());

        self::assertSame([PrincipalChoiceRequired::class], $this->recordedClasses());

        $event = $this->recordedEvent(PrincipalChoiceRequired::class);

        self::assertSame(self::GUARD, $event->context->guard);
        self::assertSame('password', $event->context->method);
        self::assertTrue($event->context->identity?->is($member)); // @phpstan-ignore method.notFound
        self::assertNull($event->context->principal);
        self::assertNull($event->context->tenant);
        self::assertNull($event->context->device);
        self::assertSame($choice->expiresAt->getTimestamp(), $event->expiresAt->getTimestamp());

        self::assertSame(0, DB::table('devices')->count());

        $row = DB::table('pending_sign_ins')->sole();

        self::assertSame(PendingSignIn::PRINCIPAL_CHOICE, $row->purpose);
        self::assertNull($row->principal_type);
        self::assertNull($row->principal_id);
        self::assertNotNull($row->attempt_windows);
    }

    /**
     * Looking a choice up does not use it up, and lists the principals eligible
     * now; choosing one signs in as it, from the client of the sign-in, and
     * uses the choice up, so looking it up again finds nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceIsLookedUpThenUsedUpByChoosing(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        $token = $this->offer();
        $found = $this->sessions(self::GUARD)->choice($token);

        self::assertInstanceOf(PrincipalChoice::class, $found);
        self::assertSame($token, $found->token);
        self::assertSame(self::GUARD, $found->guard);
        self::assertSame('password', $found->method);
        self::assertSame($member->getKey(), $found->identity->getAuthIdentifier());
        self::assertSame([$first->getKey(), $second->getKey()], self::keys($found->principals));
        self::assertSame($this->now->addSeconds(300)->getTimestamp(), $found->expiresAt->getTimestamp());

        $this->recordEvents([SignedIn::class, Login::class]);

        $result = $this->sessions(self::GUARD)->choose($token, $first);

        self::assertTrue($result->isSignedIn());
        self::assertNotNull($result->session);
        self::assertTrue($result->session->principal->is($first)); // @phpstan-ignore method.notFound
        self::assertSame('password', $result->session->method);
        self::assertTrue($result->session->deviceCreated);
        self::assertSame([Login::class, SignedIn::class], $this->recordedClasses());

        $device = DB::table('devices')->sole();

        self::assertSame(ChoosingMembership::class, $device->principal_type);
        self::assertSame((string) $first->getKey(), (string) $device->principal_id); // @phpstan-ignore cast.string
        self::assertSame(self::CLIENT_IP, $device->created_ip);

        self::assertNull($this->sessions(self::GUARD)->choice($token));
        self::assertSame(0, DB::table('pending_sign_ins')->count());
    }

    /**
     * A `start()` for an identity verified elsewhere, naming no principal,
     * waits for a choice too, with the method it named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartedSessionWaitsForAChoice(): void
    {
        [$member, $first] = $this->seedChooser();

        $result = $this->sessions(self::GUARD)->start($member, null, 'sso');

        self::assertTrue($result->requiresPrincipal());
        self::assertNotNull($result->choice);
        self::assertSame('sso', $result->choice->method);

        $chosen = $this->sessions(self::GUARD)->choose($result->choice->token, $first);

        self::assertTrue($chosen->isSignedIn());
        self::assertSame('sso', $chosen->session?->method);
    }

    /**
     * An identity with no principal it may sign in as fails as
     * `principal_unresolved` and stores nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithNoEligiblePrincipalFails(): void
    {
        $member = $this->seedChooserMember();
        $closed = ActivatableTenant::query()->create(['name' => 'Closed', 'is_active' => false]);

        ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $closed->getKey()]);

        $result = $this->sessions(self::GUARD)->signIn('password', self::credentials('chooser@example.test'));

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $result->reason);
        self::assertSame(0, DB::table('pending_sign_ins')->count());
    }

    /**
     * A guard that requires a verified identifier offers no choice to an
     * identity whose identifier is unverified: the sign-in fails as
     * `identifier_unverified`, with no choice stored or reported and no
     * principal listed, as it would with a default principal. Once the
     * identifier is verified the choice is offered.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnverifiedIdentifierIsOfferedNoChoice(): void
    {
        Schema::table('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->boolean('email_verified')->default(false);
        });

        $member = VerifiableChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $tenant = ActivatableTenant::query()->create(['name' => 'Invited', 'is_active' => true]);

        ChoosingMembership::query()->create(['identity_id' => $member->id, 'tenant_id' => $tenant->getKey()]);

        $this->recordEvents([PrincipalChoiceRequired::class, AuthenticationFailed::class]);

        $result = $this->sessions('verified')->signIn('password', self::credentials('chooser@example.test'));

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $result->reason);
        self::assertNull($result->choice);
        self::assertSame(0, DB::table('pending_sign_ins')->count());
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        $member->markIdentifierAsVerified('email', $member->email);

        self::assertTrue($this->sessions('verified')->signIn('password', self::credentials('chooser@example.test'))->requiresPrincipal());
    }

    /**
     * A guard that requires a verified identifier refuses an unverified one
     * before any principal is looked at, so the answer does not tell whether
     * the identity has a principal: `identifier_unverified` before it is
     * invited anywhere and after.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnverifiedIdentifierIsRefusedAlikeWithOrWithoutPrincipals(): void
    {
        Schema::table('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->boolean('email_verified')->default(false);
        });

        $member = VerifiableChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);

        $alone = $this->sessions('verified')->signIn('password', self::credentials('chooser@example.test'));

        $tenant = ActivatableTenant::query()->create(['name' => 'Invited', 'is_active' => true]);

        ChoosingMembership::query()->create(['identity_id' => $member->id, 'tenant_id' => $tenant->getKey()]);

        $invited = $this->sessions('verified')->signIn('password', self::credentials('chooser@example.test'));

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $alone->reason);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $invited->reason);
        self::assertSame(0, DB::table('pending_sign_ins')->count());
    }

    /**
     * A policy that refuses some principals to the identifier a sign-in used
     * (one inviting tenant's, say) keeps them out of the choice: the offer and
     * a later look-up both list only the principals it admits with that
     * identifier type, and choosing a refused one fails for its reason. A
     * choice offered to a sign-in that used no identifier lists them all.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalRefusedToTheIdentifierIsNeitherOfferedNorListed(): void
    {
        [$member, $own, $invited] = $this->seedChooser();

        app()->instance(AudiencePolicy::class, new InvitedTenantAudiencePolicy(app(AudiencePolicy::class), $invited->tenant_id));

        $offered = $this->sessions(self::GUARD)->signIn('password', self::credentials('chooser@example.test'))->choice;

        self::assertNotNull($offered);
        self::assertSame([$own->getKey()], self::keys($offered->principals));
        self::assertSame([$own->getKey()], self::keys($this->sessions(self::GUARD)->choice($offered->token)->principals ?? []));

        $refused = $this->sessions(self::GUARD)->choose($offered->token, $invited);

        self::assertTrue($refused->isFailed());
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused->reason);

        $unnamed = $this->sessions(self::GUARD)->start($member, null, 'password')->choice;

        self::assertNotNull($unnamed);
        self::assertSame([$own->getKey(), $invited->getKey()], self::keys($this->sessions(self::GUARD)->choice($unnamed->token)->principals ?? []));
    }

    /**
     * When the policy refuses every principal to the identifier the sign-in
     * used, the sign-in fails with the policy's reason rather than as if the
     * identity had no principal, storing and reporting no choice.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierRefusedEveryPrincipalFailsWithThePolicysReason(): void
    {
        $member  = $this->seedChooserMember();
        $invited = ActivatableTenant::query()->create(['name' => 'Invited', 'is_active' => true]);

        ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $invited->getKey()]);

        app()->instance(AudiencePolicy::class, new InvitedTenantAudiencePolicy(app(AudiencePolicy::class), $invited->getKey()));

        $this->recordEvents([PrincipalChoiceRequired::class]);

        $result = $this->sessions(self::GUARD)->signIn('password', self::credentials('chooser@example.test'));

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $result->reason);
        self::assertSame(0, DB::table('pending_sign_ins')->count());
        self::assertSame([], $this->recorded);
    }

    /**
     * Choosing another identity's principal fails as `principal_mismatch`, and
     * choosing one in a tenant deactivated since the choice was offered fails
     * as `tenant_inactive`; either way the choice is used up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingAPrincipalTheIdentityMayNotSignInAsFails(): void
    {
        [, $first] = $this->seedChooser();

        $other  = $this->seedChooserMember('other@example.test');
        $theirs = ChoosingMembership::query()->create(['identity_id' => $other->getKey(), 'tenant_id' => $first->tenant_id]);

        $this->recordEvents([AuthenticationFailed::class]);

        $token = $this->offer();

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $this->sessions(self::GUARD)->choose($token, $theirs)->reason);
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions(self::GUARD)->choose($token, $first)->reason);

        $reasons = array_map(static fn (AuthenticationFailed $failed): FailureReason => $failed->reason, $this->recorded);

        self::assertSame([FailureReason::PRINCIPAL_MISMATCH, FailureReason::PENDING_INVALID], $reasons);
        self::assertInstanceOf(AuthenticationFailed::class, $this->recorded[0]);
        self::assertSame(AuthenticationFlow::SIGN_IN, $this->recorded[0]->flow);

        $token = $this->offer();

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        self::assertSame(FailureReason::TENANT_INACTIVE, $this->sessions(self::GUARD)->choose($token, $first)->reason);
        self::assertNull($this->sessions(self::GUARD)->choice($token));
    }

    /**
     * A choice whose method the guard no longer allows fails as
     * `method_not_allowed`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingAfterTheMethodIsWithdrawnFails(): void
    {
        [, $first] = $this->seedChooser();

        $token = $this->offer();

        $audience = \Mockery::mock(AudiencePolicy::class);
        $audience->shouldReceive('allowsMethod')->once()->with(self::GUARD, 'password')->andReturnFalse();

        app()->instance(AudiencePolicy::class, $audience);

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions(self::GUARD)->choose($token, $first)->reason);
    }

    /**
     * A choice whose principal needs a further factor becomes a pending factor
     * for the chosen principal, carrying the choice's slots, and completing it
     * signs in as that principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceThenAFactorThenCompletionSignsIn(): void
    {
        [, , $second] = $this->seedChooser();

        $token = $this->offer();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')
            ->once()
            ->andReturnUsing(static fn (AdditionalFactorContext $context): bool => $context->principal->getPrincipalIdentifier() === $second->getKey());

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $result = $this->sessions(self::GUARD)->choose($token, $second);

        self::assertTrue($result->requiresFactor());
        self::assertNotNull($result->pending);
        self::assertTrue($result->pending->principal->is($second)); // @phpstan-ignore method.notFound

        $windows = DB::table('pending_sign_ins')->where('purpose', PendingSignIn::ADDITIONAL_FACTOR)->value('attempt_windows');

        self::assertNotNull($windows);

        $completed = $this->sessions(self::GUARD)->complete($result->pending->token);

        self::assertTrue($completed->isSignedIn());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify($completed->session?->principal->getPrincipalIdentifier()));
    }

    /**
     * Discarding a choice reports it abandoned (`principal_choice_abandoned`)
     * and it cannot be chosen afterwards; discarding it twice reports once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADiscardedChoiceIsAbandoned(): void
    {
        [$member, $first] = $this->seedChooser();

        $token = $this->offer();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertTrue($this->sessions(self::GUARD)->discard($token));
        self::assertFalse($this->sessions(self::GUARD)->discard($token));

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::PRINCIPAL_CHOICE_ABANDONED, $failed->reason);
        self::assertTrue($failed->context->identity?->is($member)); // @phpstan-ignore method.notFound
        self::assertSame('password', $failed->context->method);

        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions(self::GUARD)->choose($token, $first)->reason);
    }

    /**
     * A choice token completes no pending factor and a factor token makes no
     * choice; a choice of another guard, and a malformed token, find nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoiceAndFactorTokensAreNotInterchangeable(): void
    {
        [, $first] = $this->seedChooser();

        $choice = $this->offer();

        self::assertNull($this->sessions(self::GUARD)->pending($choice));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions(self::GUARD)->complete($choice)->reason);
        self::assertNull($this->sessions('members')->choice($choice));
        self::assertNull($this->sessions(self::GUARD)->choice('not-a-token'));
        self::assertNotNull($this->sessions(self::GUARD)->choice($choice));

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->andReturnTrue();

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $pending = $this->sessions(self::GUARD)->choose($choice, $first)->pending;

        self::assertNotNull($pending);
        self::assertNull($this->sessions(self::GUARD)->choice($pending->token));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions(self::GUARD)->choose($pending->token, $first)->reason);
        self::assertNotNull($this->sessions(self::GUARD)->pending($pending->token));
    }

    /**
     * A sign-in that proves the client holds a device for the identity offers
     * the choice with that device, reported with no principal although the
     * device records one; choosing the principal the device records continues
     * it, while choosing another starts a new one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenDeviceIsContinuedOnlyForThePrincipalItRecords(): void
    {
        [$identity, $first, $second] = $this->seedChooser();

        $session = $this->sessions(self::GUARD)->choose($this->offer(), $first)->session;

        self::assertNotNull($session);

        $this->recordEvents([PrincipalChoiceRequired::class]);

        $again   = $this->offer($session->tokens->refreshToken);
        $pending = $this->recordedEvent(PrincipalChoiceRequired::class)->context;

        self::assertSame(IdentifierCoercion::stringify($session->device->getDeviceIdentifier()), $pending->deviceId);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $pending->identityId);
        self::assertNull($pending->principal);
        self::assertNull($pending->principalType);
        self::assertNull($pending->principalId);

        $continued = $this->sessions(self::GUARD)->choose($again, $first)->session;

        self::assertNotNull($continued);
        self::assertFalse($continued->deviceCreated);
        self::assertTrue($continued->device->is($session->device)); // @phpstan-ignore method.notFound

        $other = $this->sessions(self::GUARD)->choose($this->offer($continued->tokens->refreshToken), $second)->session;

        self::assertNotNull($other);
        self::assertTrue($other->deviceCreated);
        self::assertSame(2, DB::table('devices')->count());
    }

    /**
     * The principals listed are the eligible ones, in order, as a list: one in
     * a deactivated tenant is left out wherever it falls.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsAreAListOfTheEligibleOnes(): void
    {
        [$member, $first, $second] = $this->seedChooser();

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        self::assertSame([$second->getKey()], self::keys($this->sessions(self::GUARD)->principals($member)));
    }

    /**
     * An identity that is neither its own principal nor has principals is
     * handed to the resolver, which cannot resolve it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithNoPrincipalsGoesToTheResolver(): void
    {
        $this->expectException(UnresolvableIdentityException::class);

        $this->sessions()->principals(\Mockery::mock(Identity::class));
    }

    /**
     * Choosing gives the sign-in's attempt-limit slots back once its session is
     * committed, and a failed choice keeps them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testChoosingGivesTheSlotsBackOnlyWhenASessionStarts(): void
    {
        [, $first] = $this->seedChooser();

        $limiter = new RecordingAttemptLimiter;

        app()->instance(AttemptLimiter::class, $limiter);

        $other  = $this->seedChooserMember('other@example.test');
        $theirs = ChoosingMembership::query()->create(['identity_id' => $other->getKey(), 'tenant_id' => $first->tenant_id]);

        self::assertTrue($this->sessions(self::GUARD)->choose($this->offer(), $theirs)->isFailed());
        self::assertCount(0, $limiter->released);

        self::assertTrue($this->sessions(self::GUARD)->choose($this->offer(), $first)->isSignedIn());
        self::assertCount(2, $limiter->released);
        self::assertSame(self::GUARD, $limiter->released[0]->subject->guard);
    }

    /**
     * A choice whose identity no longer resolves through the guard's provider
     * is no choice: it cannot be looked up or made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceWhoseIdentityIsGoneIsNoChoice(): void
    {
        [$member, $first] = $this->seedChooser();

        $token = $this->offer();

        $member->delete();

        self::assertNull($this->sessions(self::GUARD)->choice($token));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions(self::GUARD)->choose($token, $first)->reason);
    }

    /**
     * The principals a 2D identity may sign in as are the resolver's default,
     * itself; one the audience policy refuses has none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePrincipalsOfAnIdentityThatIsItsOwnPrincipal(): void
    {
        $identity = $this->seedIdentity();

        self::assertSame([$identity], $this->sessions()->principals($identity));

        $audience = \Mockery::mock(AudiencePolicy::class);
        $audience->shouldReceive('admit')->once()->andReturn(FailureReason::PRINCIPAL_INELIGIBLE);

        app()->instance(AudiencePolicy::class, $audience);

        self::assertSame([], $this->sessions()->principals($identity));
    }

    /**
     * Register the guards, and a guard over the choosing members.
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
        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'choosers', 'audience' => ['methods' => ['password', 'sso']]]);
        $config->set('auth.providers.verifiable_choosers', ['driver' => 'model', 'model' => VerifiableChoosingMember::class]);
        $config->set('auth.guards.verified', [
            'driver'   => 'jwt',
            'provider' => 'verifiable_choosers',
            'audience' => ['methods' => ['password'], 'require_verified_identifier' => true],
        ]);
    }

    /**
     * Persist a member with two memberships, each in its own active tenant.
     *
     * @return array{0: \Tests\Integration\Fixtures\ChoosingMember, 1: \Tests\Integration\Fixtures\ChoosingMembership, 2: \Tests\Integration\Fixtures\ChoosingMembership}
     */
    private function seedChooser(): array
    {
        $member = $this->seedChooserMember();
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
     * @param  string  $email
     * @return \Tests\Integration\Fixtures\ChoosingMember
     */
    private function seedChooserMember(string $email = 'chooser@example.test'): ChoosingMember
    {
        return ChoosingMember::query()->create(['email' => $email, 'password' => app(Hasher::class)->make(self::PASSWORD)]);
    }

    /**
     * Sign the chooser in by password and return the choice token it is
     * offered.
     *
     * @param  ?string  $refreshToken
     * @return string
     *
     * @throws \Throwable
     */
    private function offer(?string $refreshToken = null): string
    {
        $sessions = $this->sessions(self::GUARD);
        $context  = SignInContext::fromRequest(app('request'), refreshToken: $refreshToken);
        $result   = $sessions->signIn('password', self::credentials('chooser@example.test'), $context);

        self::assertNotNull($result->choice);

        return $result->choice->token;
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
