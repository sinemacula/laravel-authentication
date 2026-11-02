<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the mandatory triggers the factor package calls, through the
 * session service against a real database: a factor's removal ends the
 * identity's other sessions and judges the current one again without the
 * factor, voiding only that session's proofs made with it, keeping it, taking
 * it back to pending or revoking it; a reset ends every session; and a removed
 * first-factor credential voids nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FactorRevocations::class)]
#[CoversClass(FactorRemoval::class)]
#[CoversTrait(EndsSessions::class)]
final class FactorRevocationsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ChoosingMember`, whose members choose between their memberships. */
    private const string CHOOSERS = 'choosers';

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
     * A removal ends every other session of the identity and keeps the current
     * one while nothing is asked of it: only the current session's proofs made
     * with the removed factor are voided, another factor's stay, and the other
     * sessions' proofs are left as they are.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOtherSessionsEndAndTheCurrentOneKeepsItsOtherFactors(): void
    {
        $other   = $this->signedIn();
        $current = $this->signedIn();

        $this->stepUp($other, 'factor-a');
        $this->stepUp($current, 'factor-a');
        $this->stepUp($current, 'factor-b');
        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class, SessionReturnedToPending::class]);

        $removal = Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertSame(1, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertFalse($removal->isPending());
        self::assertNull($removal->pending);
        self::assertNull($removal->credential);
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($other->record->getKey())->revoked_reason);
        self::assertSame('active', $this->rowOf($current->record->getKey())->status);
        self::assertSame(['factor-a' => $this->now->toDateTimeString(), 'factor-b' => null], $this->voidedOn($current->record->getKey()));
        self::assertSame(['factor-a' => null], $this->voidedOn($other->record->getKey()));
        self::assertSame([SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
        self::assertSame(RevocationReason::FACTOR_REMOVED, $this->recordedEvent(SignedOutEverywhere::class)->reason);
    }

    /**
     * Without a current session, every session of the identity ends and no
     * proof is voided.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutACurrentSessionEverySessionEnds(): void
    {
        $first  = $this->signedIn();
        $second = $this->signedIn();

        $this->stepUp($second, 'factor-a');

        $removal = Auth::sessions('api')->factorRemoved($first->identity, 'factor-a');

        self::assertSame(2, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertSame(['factor-a' => null], $this->voidedOn($second->record->getKey()));
        self::assertSame(2, Session::query()->where('revoked_reason', RevocationReason::FACTOR_REMOVED->value)->count());
    }

    /**
     * A current session that met the identity's requirement only through the
     * removed factor returns to pending, waiting on a further factor: its
     * access and refresh tokens stop at once, `SessionReturnedToPending`
     * reports the `factor_change` flow, and its pending credential takes a
     * further factor that activates it again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACurrentSessionShortOfAFurtherFactorReturnsToPending(): void
    {
        $this->requireAFurtherFactor();

        $current = $this->satisfied('factor-a');

        $this->recordEvents([SessionRevoked::class, SessionReturnedToPending::class]);

        $removal = Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertTrue($removal->isPending());
        self::assertSame(0, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertNotNull($removal->pending);
        self::assertSame([PendingRequirement::MFA], $removal->pending->requires);
        self::assertFalse($removal->pending->requirement->isEmpty());
        self::assertSame($current->record->getKey(), $removal->pending->id);
        self::assertInstanceOf(Secret::class, $removal->credential);
        self::assertStringStartsWith(IdentifierCoercion::stringify($current->record->getKey()) . '.', $removal->credential->reveal());
        self::assertSame('pending', $this->rowOf($current->record->getKey())->status);
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::FACTOR_CHANGE, $this->recordedEvent(SessionReturnedToPending::class)->flow);

        self::assertFalse($this->authenticates($current->tokens->accessToken));

        $refresh = $this->sessions()->refresh((string) $current->tokens->refreshToken?->reveal());

        self::assertFalse($refresh->isRefreshed());

        $again = $this->sessions()->satisfy($removal->credential, $this->proof($current->identity, $current->record->getKey(), 'factor-b', Purpose::SIGN_IN));

        self::assertTrue($again->isSignedIn());
        self::assertSame('active', $this->rowOf($current->record->getKey())->status);
    }

    /**
     * A current session that still meets the requirement with another factor
     * stays active, its tokens working.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherFactorThatStillMeetsTheRequirementKeepsTheSessionActive(): void
    {
        $this->requireAFurtherFactor();

        $current = $this->satisfied('factor-a');

        $this->stepUp($current, 'factor-b');

        $removal = Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertFalse($removal->isPending());
        self::assertSame('active', $this->rowOf($current->record->getKey())->status);
        self::assertTrue($this->authenticates($current->tokens->accessToken));
    }

    /**
     * The tenant's further factor is judged too: a session that met its
     * tenant's requirement through the removed factor returns to pending,
     * recording the version the tenant answers now.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantsFurtherFactorIsJudgedToo(): void
    {
        $policy = new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v2', new Requirement(new RequirementPart)));

        app()->instance(TenantAuthenticationPolicy::class, $policy);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $this->seedMember();

        $current = $this->satisfied('factor-a', 'members', 'member@example.test');

        $policy->requirement = new TenantRequirement('v3', new Requirement(new RequirementPart));

        $removal = Auth::sessions('members')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertTrue($removal->isPending());
        self::assertSame('v3', $this->rowOf($current->record->getKey())->tenant_policy_version);
        self::assertSame('pending', $this->rowOf($current->record->getKey())->status);
    }

    /**
     * Rows of `[guard, email, what happened to the session meanwhile]`: a
     * current session that nothing it could do in place would take back to
     * meeting what it is asked.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \Closure(): void}>
     */
    public static function provideUnadmittableSessions(): iterable
    {
        yield 'its identity deactivated' => ['api', 'ada@example.test', static function (): void {
            IntegrationIdentity::query()->update(['is_active' => false]);
        }];

        yield 'its tenant deactivated' => ['members', 'member@example.test', static function (): void {
            ActivatableTenant::query()->update(['is_active' => false]);
        }];

        yield 'its tenant now requiring a connection' => ['members', 'member@example.test', static function (): void {
            app()->instance(TenantAuthenticationPolicy::class, new ScriptedTenantAuthenticationPolicy(new TenantRequirement(connections: ['conn-a'])));
        }];
    }

    /**
     * A current session that is no longer admitted as a refresh admits it, or
     * whose tenant now requires a connection, is revoked as `factor_removed`
     * and counted, and its revocation reported.
     *
     * @param  string  $guard
     * @param  string  $email
     * @param  \Closure(): void  $meanwhile
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnadmittableSessions')]
    public function testACurrentSessionThatCanNoLongerBeAdmittedIsRevoked(string $guard, string $email, \Closure $meanwhile): void
    {
        $this->seedIdentity();
        $this->seedMember();

        $other   = $this->signedIn($guard, $email);
        $current = $this->signedIn($guard, $email);

        $meanwhile();

        $this->recordEvents([SessionRevoked::class]);

        $removal = Auth::sessions($guard)->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertSame(2, $removal->revoked);
        self::assertTrue($removal->currentRevoked);
        self::assertFalse($removal->isPending());
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($current->record->getKey())->revoked_reason);
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($other->record->getKey())->revoked_reason);
        self::assertCount(2, $this->recorded);

        $event = $this->recorded[1];

        self::assertInstanceOf(SessionRevoked::class, $event);
        self::assertSame($current->record->getKey(), $event->context->session?->getSessionIdentifier());
    }

    /**
     * Rows of `[what ended the current session meanwhile]`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): void}>
     */
    public static function provideEndedSessions(): iterable
    {
        yield 'revoked' => [static function (SignedInSession $current): void {
            Session::query()->whereKey($current->record->getKey())->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked']);
        }];

        yield 'past its idle deadline' => [static function (SignedInSession $current): void {
            Session::query()->whereKey($current->record->getKey())->update(['idle_expires_at' => CarbonImmutable::now()->subSecond()]);
        }];

        yield 'pending and past its idle deadline' => [static function (SignedInSession $current): void {
            Session::query()->whereKey($current->record->getKey())->update(['status' => 'pending', 'idle_expires_at' => CarbonImmutable::now()->subSecond()]);
        }];

        yield 'deleted' => [static function (SignedInSession $current): void {
            Session::query()->whereKey($current->record->getKey())->delete();
        }];

        yield 'its key held by another owner' => [static function (SignedInSession $current): void {
            Session::query()->whereKey($current->record->getKey())->update(['authenticatable_id' => '999']);
        }];
    }

    /**
     * A current session that has meanwhile been revoked, ended (pending or not)
     * or been replaced is left as it is: neither voided, judged nor counted.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): void  $meanwhile
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEndedSessions')]
    public function testACurrentSessionThatEndedMeanwhileIsLeftAsItIs(\Closure $meanwhile): void
    {
        $current = $this->signedIn();

        $this->stepUp($current, 'factor-a');

        $before = $this->columnsOf($current->record->getKey());

        $meanwhile($current);

        $during = $this->columnsOf($current->record->getKey());

        $removal = Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertNotSame($before, $during);
        self::assertSame(0, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertFalse($removal->isPending());
        self::assertSame($during, $this->columnsOf($current->record->getKey()));
        self::assertSame(['factor-a' => null], $this->voidedOn($current->record->getKey()));
    }

    /**
     * A current session that is pending, live and still the session given has
     * its proofs made with the removed factor voided, another factor's kept,
     * and stays pending as it was: nothing else of it is written, judged or
     * counted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingCurrentSessionHasTheFactorsProofsVoidedAndStaysPending(): void
    {
        $current = $this->signedIn();

        $this->stepUp($current, 'factor-a');
        $this->stepUp($current, 'factor-b');

        Session::query()->whereKey($current->record->getKey())->update(['status' => 'pending']);

        $during = $this->columnsOf($current->record->getKey());

        $this->recordEvents([SessionRevoked::class, SessionReturnedToPending::class]);

        $removal = Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertSame(0, $removal->revoked);
        self::assertFalse($removal->currentRevoked);
        self::assertFalse($removal->isPending());
        self::assertSame($during, $this->columnsOf($current->record->getKey()));
        self::assertSame(['factor-a' => $this->now->toDateTimeString(), 'factor-b' => null], $this->voidedOn($current->record->getKey()));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A pending session waiting only on the principal choice, having met its
     * further factor with the factor removed, no longer meets it: the choice it
     * makes next leaves it pending on a further factor, not active.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChoiceMadeAfterTheRemovalStaysPendingOnAFurtherFactor(): void
    {
        $this->requireAFurtherFactor();

        $member      = ChoosingMember::query()->create(['email' => 'chooser@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)]);
        $memberships = [];

        foreach (['First', 'Second'] as $name) {
            $tenant        = ActivatableTenant::query()->create(['name' => $name, 'is_active' => true]);
            $memberships[] = ChoosingMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        }

        $signIn = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'));

        self::assertNotNull($signIn->pending);
        self::assertNotNull($signIn->credential);
        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], $signIn->pending->requires);

        $moved = $this->sessions(self::CHOOSERS)->satisfy($signIn->credential, $this->proof($member, $signIn->pending->id, 'factor-a', Purpose::SIGN_IN, self::CHOOSERS));

        self::assertSame([PendingRequirement::PRINCIPAL], $moved->pending?->requires);

        $record  = Session::query()->whereKey($signIn->pending->id)->firstOrFail();
        $removal = Auth::sessions(self::CHOOSERS)->factorRemoved($member, 'factor-a', $record);

        self::assertFalse($removal->isPending());
        self::assertSame(['factor-a' => $this->now->toDateTimeString()], $this->voidedOn($record->getKey()));

        $chosen = $this->sessions(self::CHOOSERS)->choose($signIn->credential, $memberships[0]);

        self::assertTrue($chosen->isPending());
        self::assertNull($chosen->session);
        self::assertSame([PendingRequirement::MFA], $chosen->pending?->requires);
        self::assertSame('pending', $this->rowOf($record->getKey())->status);
    }

    /**
     * The guard bound to the current session forgets it once the removal that
     * took it back to pending commits, not before; one that stays active stays
     * bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardForgetsTheCurrentSessionOnceTheRemovalCommits(): void
    {
        $this->requireAFurtherFactor();

        $current = $this->satisfied('factor-a');
        $guard   = $this->boundGuard($current);

        DB::transaction(function () use ($current, $guard): void {

            self::assertTrue(Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record)->isPending());
            self::assertNotNull($guard->session());
        });

        self::assertNull($guard->session());
        self::assertNull($guard->user());
    }

    /**
     * A revoked current session is forgotten by the guard bound to it once the
     * removal commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardForgetsARevokedCurrentSession(): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        IntegrationIdentity::query()->update(['is_active' => false]);

        self::assertTrue(Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record)->currentRevoked);
        self::assertNull($guard->session());
    }

    /**
     * A current session that stays active keeps the guard bound to it, and a
     * guard bound to another session of the identity is not touched by the
     * removal's recheck.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACurrentSessionThatStaysActiveStaysBound(): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertSame($current->record->getKey(), $guard->session()?->getSessionIdentifier());
    }

    /**
     * Rows of `[the removal's arguments, the message expected]`: a factor that
     * names nothing, one too long, and a current session that is not one of the
     * identity's on this guard.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Feature\Sessions\FactorRevocationsTest, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): array{0: string, 1: ?\SineMacula\Laravel\Authentication\Contracts\Session}, 1: string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideRefusedArguments(): iterable
    {
        $factor  = 'A removed factor is named by its reference, of 1 to 255 characters.';
        $session = 'The current session of a factor\'s removal must be a session of guard [api] that the identity owns.';

        yield 'an empty factor' => [static fn (self $test, SignedInSession $current): array => ['', $current->record], $factor];
        yield 'a factor too long' => [static fn (self $test, SignedInSession $current): array => [str_repeat('f', 256), $current->record], $factor];
        yield 'another identity\'s session' => [static fn (self $test, SignedInSession $current): array => ['factor-a', $test->anotherIdentitysSession()], $session];
        yield 'another guard\'s session' => [static fn (self $test, SignedInSession $current): array => ['factor-a', $test->anotherGuardsSession()], $session];
    }

    /**
     * A removal whose factor names nothing, or whose current session is not one
     * of the identity's on this guard, is refused before anything is written or
     * reported.
     *
     * @param  \Closure(self, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): array{0: string, 1: ?\SineMacula\Laravel\Authentication\Contracts\Session}  $arguments
     * @param  string  $message
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedArguments')]
    public function testARemovalWithArgumentsThatDoNotHoldIsRefusedBeforeAnythingIsWritten(\Closure $arguments, string $message): void
    {
        $current = $this->signedIn();

        $this->stepUp($current, 'factor-a');

        [$factor, $session] = $arguments($this, $current);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        try {
            Auth::sessions('api')->factorRemoved($current->identity, $factor, $session);

            self::fail('Expected the removal to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame($message, $exception->getMessage());
        }

        self::assertSame(0, Session::query()->whereNotNull('revoked_at')->count());
        self::assertSame(['factor-a' => null], $this->voidedOn($current->record->getKey()));
        self::assertSame([], $this->recorded);
    }

    /**
     * A factor of exactly 255 characters is a factor.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorOfTheLongestLengthIsAccepted(): void
    {
        $current = $this->signedIn();
        $factor  = str_repeat('é', 255);

        $this->stepUp($current, $factor);

        Auth::sessions('api')->factorRemoved($current->identity, $factor, $current->record);

        self::assertSame([$factor => $this->now->toDateTimeString()], $this->voidedOn($current->record->getKey()));
    }

    /**
     * Rows of `[the trigger, its flow's name]`.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity): mixed, 1: string}>
     */
    public static function provideTriggers(): iterable
    {
        yield 'a removal' => [static fn (Identity $identity): mixed => Auth::sessions('api')->factorRemoved($identity, 'factor-a'), 'A factor\'s removal'];
        yield 'a reset' => [static fn (Identity $identity): mixed => Auth::sessions('api')->factorReset($identity), 'A reset of factors'];
    }

    /**
     * An identity that does not live on the storage connection is refused
     * before anything is written: its cutoff and its sessions would not end in
     * the factor package's transaction.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Contracts\Identity): mixed  $trigger
     * @param  string  $flow
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTriggers')]
    public function testAnIdentityOffTheStorageConnectionIsRefused(\Closure $trigger, string $flow): void
    {
        $current  = $this->signedIn();
        $identity = $current->identity;

        self::assertInstanceOf(IntegrationIdentity::class, $identity);

        $identity->setConnection('elsewhere');

        try {
            $trigger($identity);

            self::fail('Expected the trigger to be refused.');
        } catch (\LogicException $exception) {
            self::assertStringStartsWith($flow . ' moves the identity\'s cutoff and ends its sessions in the factor package\'s transaction, so ', $exception->getMessage());
            self::assertStringContainsString('[elsewhere]', $exception->getMessage());
        }

        self::assertSame(0, Session::query()->whereNotNull('revoked_at')->count());
    }

    /**
     * A reset ends every session of the identity, the current one included, as
     * `factor_reset`, and reports the bulk revocation with that reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetEndsEverySessionTheCurrentOneIncluded(): void
    {
        $first = $this->signedIn();

        $this->signedIn();
        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(2, Auth::sessions('api')->factorReset($first->identity));
        self::assertSame(2, Session::query()->where('revoked_reason', RevocationReason::FACTOR_RESET->value)->count());
        self::assertSame(RevocationReason::FACTOR_RESET, $this->recordedEvent(SignedOutEverywhere::class)->reason);
    }

    /**
     * A reset forgets the binding of a guard bound to the identity once it
     * commits, not before and not when it rolls back, so the rest of the
     * request is not authenticated as a session it ended; a guard bound to
     * another identity stays bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetForgetsTheGuardBoundToTheIdentityOnceItCommits(): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        try {
            DB::transaction(static function () use ($current): void {

                Auth::sessions('api')->factorReset($current->identity);

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException) {
            self::assertTrue($guard->check());
        }

        DB::transaction(static function () use ($current, $guard): void {

            self::assertSame(1, Auth::sessions('api')->factorReset($current->identity));
            self::assertTrue($guard->check());
        });

        self::assertFalse($guard->check());
        self::assertNull($guard->session());
        self::assertFalse(Auth::guard('api')->check());

        $other = $this->signedIn('api', 'grace@example.test');
        $kept  = $this->boundGuard($other);

        Auth::sessions('api')->factorReset($current->identity);

        self::assertSame($other->record->getKey(), $kept->session()?->getSessionIdentifier());
    }

    /**
     * A removal given no current session ends every session of the identity, so
     * it forgets the binding of a guard bound to the identity once it commits,
     * as a reset does: not before and not when it rolls back, and a guard bound
     * to another identity stays bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalWithoutACurrentSessionForgetsTheGuardBoundToTheIdentityOnceItCommits(): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        try {
            DB::transaction(static function () use ($current): void {

                Auth::sessions('api')->factorRemoved($current->identity, 'factor-a');

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException) {
            self::assertTrue($guard->check());
        }

        DB::transaction(static function () use ($current, $guard): void {

            self::assertSame(1, Auth::sessions('api')->factorRemoved($current->identity, 'factor-a')->revoked);
            self::assertTrue($guard->check());
        });

        self::assertFalse($guard->check());
        self::assertNull($guard->session());
        self::assertFalse(Auth::guard('api')->check());

        $other = $this->signedIn('api', 'grace@example.test');
        $kept  = $this->boundGuard($other);

        Auth::sessions('api')->factorRemoved($current->identity, 'factor-a');

        self::assertSame($other->record->getKey(), $kept->session()?->getSessionIdentifier());
    }

    /**
     * A removed first-factor credential ends the identity's other sessions,
     * keeps the current one and voids no proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovedCredentialVoidsNothing(): void
    {
        $other   = $this->signedIn();
        $current = $this->signedIn();

        $this->stepUp($current, 'factor-a');

        self::assertSame(1, Auth::sessions('api')->credentialRemoved($current->identity, $current->record));
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($other->record->getKey())->revoked_reason);
        self::assertSame('active', $this->rowOf($current->record->getKey())->status);
        self::assertSame(['factor-a' => null], $this->voidedOn($current->record->getKey()));
    }

    /**
     * Another identity's session on this guard.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    public function anotherIdentitysSession(): Session
    {
        $this->seedIdentity('grace@example.test');

        $result = $this->sessions()->signIn('password', self::credentials('grace@example.test'));

        self::assertInstanceOf(Session::class, $result->session?->record);

        return $result->session->record;
    }

    /**
     * The identity's own session on another guard.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    public function anotherGuardsSession(): Session
    {
        $result = $this->sessions('admin')->signIn('password', self::credentials());

        self::assertInstanceOf(Session::class, $result->session?->record);

        return $result->session->record;
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.choosers', ['driver' => 'model', 'model' => ChoosingMember::class]);
        $config->set('auth.guards.' . self::CHOOSERS, ['driver' => 'jwt', 'provider' => 'choosers', 'application' => ['methods' => ['password']]]);
    }

    /**
     * A session the identity with the email signed in to with its password now,
     * seeding the 2D identity when it is the default one and does not exist
     * yet.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        if ($guard === 'api' && !IntegrationIdentity::query()->where('email', $email)->exists()) {
            $this->seedIdentity($email);
        }

        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Ask every sign-in of the identity for a further factor, met by any
     * accepted further factor the session holds.
     *
     * @return void
     */
    private function requireAFurtherFactor(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
    }

    /**
     * A session that signed in pending a further factor and was activated with
     * the factor given.
     *
     * @param  string  $factor
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function satisfied(string $factor, string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        if ($guard === 'api') {
            $this->seedIdentity($email);
        }

        $pending = $this->sessions($guard)->signIn('password', self::credentials($email));

        self::assertTrue($pending->isPending());
        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $result = Auth::sessions($guard)->satisfy($pending->credential, $this->proof($pending->pending->identity, $pending->pending->id, $factor, Purpose::SIGN_IN, $guard));

        self::assertNotNull($result->session);

        return $result->session;
    }

    /**
     * Step the session up with the factor given, now.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @param  string  $factor
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUp(SignedInSession $signedIn, string $factor): void
    {
        $guard = (string) $signedIn->record->getGuard();

        self::assertTrue($this->sessions($guard)->stepUp($this->proof($signedIn->identity, $signedIn->record->getKey(), $factor, Purpose::STEP_UP, $guard))->isIssued());
    }

    /**
     * An accepted further factor's proof, made now with the factor given, for
     * the session and purpose given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $sessionId
     * @param  string  $factor
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    private function proof(Identity $identity, mixed $sessionId, string $factor, Purpose $purpose, string $guard = 'api'): ProofResult
    {
        return new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            $factor,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($identity, $guard, $sessionId, $purpose),
        );
    }

    /**
     * The `api` guard, resolved afresh and bound to the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $signedIn
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function boundGuard(SignedInSession $signedIn): JwtGuard
    {
        $guard = $this->freshGuard();

        $guard->login($signedIn->identity, $signedIn->principal, $signedIn->record);

        self::assertSame($signedIn->record->getKey(), $guard->session()?->getSessionIdentifier());

        return $guard;
    }

    /**
     * Whether the access token authenticates a request on the `api` guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $token
     * @return bool
     */
    private function authenticates(Secret $token): bool
    {
        Auth::forgetGuards();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard->setRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token->reveal()]))->user() !== null;
    }

    /**
     * The stored row of the session with the key given.
     *
     * @param  mixed  $key
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function rowOf(mixed $key): Session
    {
        return Session::query()->whereKey($key)->firstOrFail();
    }

    /**
     * The stored columns of the session with the key given, or `null` when
     * there is none.
     *
     * @param  mixed  $key
     * @return ?array<string, mixed>
     */
    private function columnsOf(mixed $key): ?array
    {
        return Session::query()->whereKey($key)->first()?->getAttributes();
    }

    /**
     * When each proof the session recorded with a factor was voided, by its
     * factor, `null` for one that still counts.
     *
     * @param  mixed  $key
     * @return array<string, ?string>
     */
    private function voidedOn(mixed $key): array
    {
        /** @var array<string, ?string> */
        return DB::table('authentication_proofs')
            ->where('session_id', IdentifierCoercion::stringify($key))
            ->whereNotNull('factor_reference')
            ->orderBy('authenticated_at')
            ->orderBy('factor_reference')
            ->pluck('voided_at', 'factor_reference')
            ->all();
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
