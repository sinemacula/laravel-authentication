<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
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
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ChoosingMember;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\StubNonModelSession;

/**
 * Feature tests of the mandatory triggers the factor package calls when an
 * identity's factors change.
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
    use InspectsIssuanceGuards, InteractsWithSessions, MarksSharedLocks;

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
     * A removal ends the other sessions and voids only the current one's proofs
     * with the factor.
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

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        $removal = Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        $guard = array_key_first(array_filter($statements, static fn (string $sql): bool => str_contains($sql, 'issuance_sequence')));
        $void  = array_key_first(array_filter($statements, static fn (string $sql): bool => str_contains($sql, 'voided_at') && str_starts_with($sql, 'update')));

        self::assertIsInt($guard);
        self::assertIsInt($void);
        self::assertLessThan($void, $guard);
        self::assertSame(3, self::issuanceGuardWrites($current->record->getKey()));
        self::assertSame(1, self::issuanceGuardWrites($other->record->getKey()));
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
     * Without a current session every session of the identity ends and no proof
     * is voided.
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
     * A current session short of a further factor returns to pending.
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

        $refresh = $this->sessions()->refresh(PresentedRefreshToken::fromBody((string) $current->tokens->refreshToken?->reveal()), self::requestClient());

        self::assertFalse($refresh->isRefreshed());

        $again = $this->sessions()->satisfy(
            $removal->credential,
            $this->proof($current->identity, $current->record->getKey(), 'factor-b', Purpose::SIGN_IN),
            self::requestClient(),
        );

        self::assertTrue($again->isSignedIn());
        self::assertSame('active', $this->rowOf($current->record->getKey())->status);
    }

    /**
     * Rows of `[write to the current session during the removal, whether the
     * removal revokes it]`.
     *
     * @return iterable<string, array{0: array<string, ?string>, 1: bool}>
     */
    public static function provideWritesDuringTheJudgement(): iterable
    {
        yield 'its refresh token rotated' => [['refresh_key' => str_repeat('0', 64)], true];
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'signed_out', 'refresh_key' => null], false];
    }

    /**
     * A current session written during its judgement is revoked, never left
     * active.
     *
     * @param  array<string, ?string>  $write
     * @param  bool  $ownRevocation
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideWritesDuringTheJudgement')]
    public function testACurrentSessionWrittenDuringItsJudgementIsRevoked(array $write, bool $ownRevocation): void
    {
        $this->requireAFurtherFactor();

        $current = $this->satisfied('factor-a');
        $key     = $current->record->getKey();

        app()->instance(RequirementCheck::class, self::writingCheck($key, $write));

        $removal = Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        self::assertFalse($removal->isPending());
        self::assertSame($ownRevocation, $removal->currentRevoked);
        self::assertSame($ownRevocation ? 1 : 0, $removal->revoked);
        self::assertSame($ownRevocation ? RevocationReason::FACTOR_REMOVED->value : 'signed_out', $this->rowOf($key)->revoked_reason);
        self::assertSame('active', $this->rowOf($key)->status);
    }

    /**
     * A session that still meets the requirement with another factor stays
     * active.
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
     * A session that met its tenant's requirement through the removed factor
     * returns to pending.
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
     * Rows of `[guard, email, what happened to the session meanwhile]` for a
     * session no longer admitted.
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
     * A current session that can no longer be admitted is revoked as
     * `factor_removed`.
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
        self::assertSame($current->record->getKey(), $event->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($current->record->getAttribute('principal_id')), $event->context->principalId);
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
     * A current session that ended meanwhile is neither voided, judged nor
     * counted.
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
     * A pending current session has the factor's proofs voided and stays
     * pending.
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
        self::assertIsArray($during);
        self::assertSame([...$during, 'issuance_sequence' => 3], $this->columnsOf($current->record->getKey()));
        self::assertSame(['factor-a' => $this->now->toDateTimeString(), 'factor-b' => null], $this->voidedOn($current->record->getKey()));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A choice made after the removal stays pending on a further factor.
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

        $signIn = $this->sessions(self::CHOOSERS)->signIn('password', self::credentials('chooser@example.test'), self::requestContext());

        self::assertNotNull($signIn->pending);
        self::assertNotNull($signIn->credential);
        self::assertSame([PendingRequirement::MFA, PendingRequirement::PRINCIPAL], $signIn->pending->requires);

        $moved = $this->sessions(self::CHOOSERS)->satisfy(
            $signIn->credential,
            $this->proof($member, $signIn->pending->id, 'factor-a', Purpose::SIGN_IN, self::CHOOSERS),
            self::requestClient(),
        );

        self::assertSame([PendingRequirement::PRINCIPAL], $moved->pending?->requires);

        $record  = Session::query()->whereKey($signIn->pending->id)->firstOrFail();
        $removal = Auth::sessions(self::CHOOSERS)->factorRemoved($member, 'factor-a', $record);

        self::assertFalse($removal->isPending());
        self::assertSame(['factor-a' => $this->now->toDateTimeString()], $this->voidedOn($record->getKey()));

        $chosen = $this->sessions(self::CHOOSERS)->choose($signIn->credential, $memberships[0], self::requestClient());

        self::assertTrue($chosen->isPending());
        self::assertNull($chosen->session);
        self::assertSame([PendingRequirement::MFA], $chosen->pending?->requires);
        self::assertSame('pending', $this->rowOf($record->getKey())->status);
    }

    /**
     * The guard forgets a current session returned to pending once the removal
     * commits.
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
     * A current session that stays active stays bound, and other bindings are
     * untouched.
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
     * A voided proof is forgotten from the bound guard's context at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAVoidedProofIsForgottenFromTheContextAtOnce(): void
    {
        $current = $this->signedIn();

        $this->stepUp($current, 'factor-a');

        $guard = $this->boundGuard($current);
        $held  = $guard->authenticationContext();

        self::assertTrue($held?->mfa);

        DB::beginTransaction();

        Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

        $inside = $guard->authenticationContext();

        self::assertNotSame($held, $inside);
        self::assertFalse($inside?->mfa);

        DB::rollBack();

        self::assertTrue($guard->authenticationContext()?->mfa);

        DB::transaction(static function () use ($current, $guard): void {

            Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record);

            self::assertFalse($guard->authenticationContext()->mfa);
        });

        $after = $guard->authenticationContext();

        self::assertNotNull($after);
        self::assertFalse($after->mfa);
        self::assertSame($current->record->getKey(), $guard->session()?->getSessionIdentifier());
    }

    /**
     * Rows of `[the removal's arguments, the message expected]`.
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
        yield 'a session of the guard that is not a model' => [static fn (self $test, SignedInSession $current): array => ['factor-a', self::nonModelSession()], $session];
    }

    /**
     * A removal with invalid arguments is refused before anything is written.
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
     * An identity off the storage connection is refused before anything is
     * written.
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
     * A reset ends every session of the identity as `factor_reset`, the current
     * one included.
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
     * A reset forgets a guard bound to the identity once it commits.
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
     * A removal without a current session forgets a guard bound to the identity
     * once it commits.
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
     * Rows of a change that ends every session of the identity.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): mixed}>
     */
    public static function provideEndingsOfEverySession(): iterable
    {
        yield 'a reset' => [static fn (SignedInSession $current): int => Auth::sessions('api')->factorReset($current->identity)];
        yield 'a removal without a current session' => [
            static fn (SignedInSession $current): FactorRemoval => Auth::sessions('api')->factorRemoved($current->identity, 'factor-a'),
        ];
    }

    /**
     * Ending every session forgets every guard bound to the identity on commit.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): mixed  $ending
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEndingsOfEverySession')]
    public function testAnEndingOfEverySessionForgetsEveryGuardBoundToTheIdentityOnceItCommits(\Closure $ending): void
    {
        $api   = $this->signedIn();
        $admin = $this->signedIn('admin');

        [$apiGuard, $adminGuard] = $this->boundGuards($api, $admin);

        try {
            DB::transaction(static function () use ($ending, $api): void {

                $ending($api);

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException) {
            self::assertTrue($apiGuard->check());
            self::assertTrue($adminGuard->check());
        }

        DB::transaction(static function () use ($ending, $api, $adminGuard): void {

            $ending($api);

            self::assertTrue($adminGuard->check());
        });

        self::assertFalse($apiGuard->check());
        self::assertFalse($adminGuard->check());
        self::assertNull($adminGuard->session());
    }

    /**
     * A removal keeps the current session's guard and forgets the others.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARemovalForgetsEveryOtherGuardBoundToTheIdentityButKeepsTheCurrentSessions(): void
    {
        $current = $this->signedIn();
        $other   = $this->signedIn('admin');

        [$currentGuard, $otherGuard] = $this->boundGuards($current, $other);

        DB::transaction(static function () use ($current, $otherGuard): void {

            self::assertSame(1, Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record)->revoked);
            self::assertTrue($otherGuard->check());
        });

        self::assertSame($current->record->getKey(), $currentGuard->session()?->getSessionIdentifier());
        self::assertFalse($otherGuard->check());
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($other->record->getKey())->revoked_reason);
    }

    /**
     * A listener that throws leaves the guard unbound from the identity.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): mixed  $ending
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEndingsOfEverySession')]
    public function testAListenerThatThrowsLeavesTheGuardUnboundFromTheIdentity(\Closure $ending): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        $this->throwOnRevocation();

        self::assertSame('listener failed', self::failureOf(static fn (): mixed => $ending($current)));
        self::assertFalse($guard->check());
        self::assertNull($guard->session());
        self::assertNotNull($this->rowOf($current->record->getKey())->revoked_at);
    }

    /**
     * A listener that throws leaves the guard unbound from a session returned
     * to pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListenerThatThrowsLeavesTheGuardUnboundFromACurrentSessionReturnedToPending(): void
    {
        $this->requireAFurtherFactor();

        $current = $this->satisfied('factor-a');
        $other   = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->pending;
        $guard   = $this->boundGuard($current);

        self::assertNotNull($other);

        $this->throwOnRevocation();

        self::assertSame('listener failed', self::failureOf(static fn (): FactorRemoval => Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record)));
        self::assertNull($guard->session());
        self::assertSame('pending', $this->rowOf($current->record->getKey())->status);
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($other->id)->revoked_reason);
    }

    /**
     * A listener that throws leaves the guard unbound from a revoked current
     * session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListenerThatThrowsLeavesTheGuardUnboundFromARevokedCurrentSession(): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        IntegrationIdentity::query()->update(['is_active' => false]);

        $this->throwOnRevocation();

        self::assertSame('listener failed', self::failureOf(static fn (): FactorRemoval => Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record)));
        self::assertNull($guard->session());
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($current->record->getKey())->revoked_reason);
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
     * A factor change that leaves the current session short returns it to
     * pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFactorChangeThatLeavesTheCurrentSessionShortReturnsItToPending(): void
    {
        $current = $this->signedIn();

        $this->requireAFurtherFactor();
        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class, SessionReturnedToPending::class]);

        $change = Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertTrue($change->isPending());
        self::assertSame(FactorChangeStatus::PENDING, $change->status);
        self::assertNotNull($change->pending);
        self::assertSame([PendingRequirement::MFA], $change->pending->requires);
        self::assertFalse($change->pending->requirement->isEmpty());
        self::assertSame($current->record->getKey(), $change->pending->id);
        self::assertInstanceOf(Secret::class, $change->credential);
        self::assertStringStartsWith(IdentifierCoercion::stringify($current->record->getKey()) . '.', $change->credential->reveal());
        self::assertSame('pending', $this->rowOf($current->record->getKey())->status);
        self::assertNull($this->rowOf($current->record->getKey())->revoked_at);
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::FACTOR_CHANGE, $this->recordedEvent(SessionReturnedToPending::class)->flow);

        self::assertFalse($this->authenticates($current->tokens->accessToken));
        self::assertFalse($this->sessions()->refresh(PresentedRefreshToken::fromBody((string) $current->tokens->refreshToken?->reveal()), self::requestClient())->isRefreshed());

        $again = $this->sessions()->satisfy($change->credential, $this->proof($current->identity, $current->record->getKey(), 'factor-a', Purpose::SIGN_IN), self::requestClient());

        self::assertTrue($again->isSignedIn());
        self::assertSame($current->record->getKey(), $again->session?->record->getKey());
        self::assertSame('active', $this->rowOf($current->record->getKey())->status);
    }

    /**
     * A change judges the tenant's further factor too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeJudgesTheTenantsFurtherFactorToo(): void
    {
        $policy = new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v2'));

        app()->instance(TenantAuthenticationPolicy::class, $policy);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $this->seedMember();

        $current = $this->signedIn('members', 'member@example.test');

        self::assertSame('v2', $this->rowOf($current->record->getKey())->tenant_policy_version);

        $policy->requirement = new TenantRequirement('v3', new Requirement(new RequirementPart));

        $change = Auth::sessions('members')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertTrue($change->isPending());
        self::assertSame('pending', $this->rowOf($current->record->getKey())->status);
        self::assertSame('v3', $this->rowOf($current->record->getKey())->tenant_policy_version);
    }

    /**
     * A change and a removal read the current session's proofs with a shared
     * lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeAndARemovalReadTheProofsCurrent(): void
    {
        $policy = new ScriptedTenantAuthenticationPolicy(new TenantRequirement('v1', new Requirement(new RequirementPart)));

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        $this->requireAFurtherFactor();
        $this->seedMember();

        $current = $this->satisfied('factor-1', 'members', 'member@example.test');

        $this->stepUp($current, 'factor-2');

        self::markSharedLocks();

        $locked = self::takesSharedLocks();

        $change = self::proofReadLocks(static function () use ($current): void {
            self::assertTrue(Auth::sessions('members')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record)->isActive());
        });

        $removal = self::proofReadLocks(static function () use ($current): void {
            self::assertFalse(Auth::sessions('members')->factorRemoved($current->identity, 'factor-1', $current->record)->isPending());
        });

        $policy->requirement = new TenantRequirement('v2');

        $unasked = self::proofReadLocks(static function () use ($current): void {
            self::assertTrue(Auth::sessions('members')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record)->isActive());
        });

        self::assertSame([$locked, $locked, $locked], $change);
        self::assertSame([$locked, $locked, $locked], $removal);
        self::assertSame([$locked, $locked], $unasked);
    }

    /**
     * Rows of every change the factor package names.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade}>
     */
    public static function provideChangesMade(): iterable
    {
        foreach (FactorChangeMade::cases() as $change) {
            yield $change->value => [$change];
        }
    }

    /**
     * Every change judges only the current session and writes nothing else.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesMade')]
    public function testEveryChangeJudgesOnlyTheCurrentSession(FactorChangeMade $change): void
    {
        $other   = $this->signedIn();
        $current = $this->signedIn();

        $this->stepUp($other, 'factor-a');
        $this->requireAFurtherFactor();

        $pending = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->pending;

        self::assertNotNull($pending);

        $changeId = hash('sha256', 'change-1');

        DB::table('identifier_changes')->insert([
            'id'           => $changeId,
            'guard'        => 'api',
            'type'         => 'email',
            'previous'     => null,
            'identifier'   => 'ada@new.example.test',
            'request_id'   => '0195f4a2-7b1c-4000-8000-000000000001',
            'requested_at' => '2026-04-06 12:00:00',
            'expires_at'   => '2026-04-06 13:00:00',
        ]);

        $otherBefore    = $this->columnsOf($other->record->getKey());
        $pendingBefore  = $this->columnsOf($pending->id);
        $identityBefore = IntegrationIdentity::query()->sole()->getAttributes();

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class, SessionReturnedToPending::class]);

        self::assertTrue(Auth::sessions('api')->factorChanged($current->identity, $change, $current->record)->isPending());
        self::assertSame($otherBefore, $this->columnsOf($other->record->getKey()));
        self::assertSame($pendingBefore, $this->columnsOf($pending->id));
        self::assertSame($identityBefore, IntegrationIdentity::query()->sole()->getAttributes());
        self::assertSame([$changeId], DB::table('identifier_changes')->pluck('id')->all());
        self::assertSame(['factor-a' => null], $this->voidedOn($other->record->getKey()));
        self::assertSame(0, Session::query()->whereNotNull('revoked_at')->count());
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
    }

    /**
     * A current session that still meets what it is asked stays active and
     * bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACurrentSessionThatStillMeetsWhatItIsAskedStaysActive(): void
    {
        $this->requireAFurtherFactor();

        $current = $this->satisfied('factor-a');
        $guard   = $this->boundGuard($current);
        $held    = $guard->authenticationContext();
        $before  = $this->columnsOf($current->record->getKey());

        self::assertIsArray($before);
        self::assertIsInt($before['issuance_sequence']);

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class, SessionReturnedToPending::class]);

        $statements = [];

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        $change = Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        $issuance = array_key_first(array_filter($statements, static fn (string $sql): bool => str_contains($sql, 'issuance_sequence')));
        $proofs   = array_key_first(array_filter($statements, static fn (string $sql): bool => str_contains($sql, 'authentication_proofs')));

        self::assertTrue($change->isActive());
        self::assertNull($change->pending);
        self::assertNull($change->credential);
        self::assertIsInt($issuance);
        self::assertIsInt($proofs);
        self::assertLessThan($proofs, $issuance);
        self::assertSame([...$before, 'issuance_sequence' => $before['issuance_sequence'] + 1], $this->columnsOf($current->record->getKey()));
        self::assertSame(['factor-a' => null], $this->voidedOn($current->record->getKey()));
        self::assertSame([], $this->recordedClasses());
        self::assertSame($current->record->getKey(), $guard->session()?->getSessionIdentifier());
        self::assertSame($held, $guard->authenticationContext());
        self::assertTrue($this->authenticates($current->tokens->accessToken));
    }

    /**
     * Rows of `[guard, email, what happened meanwhile, change, revocation
     * reason]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: string, 1: string, 2: \Closure(): void, 3: \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade, 4: \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideUnadmittableSessionsAfterAChange(): iterable
    {
        foreach (self::provideUnadmittableSessions() as $name => [$guard, $email, $meanwhile]) {
            yield "{$name}, after a factor confirmed" => [$guard, $email, $meanwhile, FactorChangeMade::FACTOR_CONFIRMED, RevocationReason::FACTOR_CHANGED];
            yield "{$name}, after a passkey factor registered" => [$guard, $email, $meanwhile, FactorChangeMade::PASSKEY_FACTOR_REGISTERED, RevocationReason::FACTOR_CHANGED];
            yield "{$name}, after another change" => [$guard, $email, $meanwhile, FactorChangeMade::OTHER, RevocationReason::FACTOR_CHANGED];
            yield "{$name}, after a factor removed" => [$guard, $email, $meanwhile, FactorChangeMade::FACTOR_REMOVED, RevocationReason::FACTOR_REMOVED];
        }
    }

    /**
     * A current session no longer admitted is revoked with the change's reason.
     *
     * @param  string  $guard
     * @param  string  $email
     * @param  \Closure(): void  $meanwhile
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideUnadmittableSessionsAfterAChange')]
    public function testACurrentSessionNoLongerAdmittedIsRevokedWithTheChangesReason(
        string $guard,
        string $email,
        \Closure $meanwhile,
        FactorChangeMade $change,
        RevocationReason $reason,
    ): void {
        $this->seedIdentity();
        $this->seedMember();

        $other   = $this->signedIn($guard, $email);
        $current = $this->signedIn($guard, $email);

        $meanwhile();

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class, SessionReturnedToPending::class]);

        $result = Auth::sessions($guard)->factorChanged($current->identity, $change, $current->record);

        self::assertTrue($result->isRevoked());
        self::assertSame(FactorChangeStatus::REVOKED, $result->status);
        self::assertNull($result->pending);
        self::assertNull($result->credential);
        self::assertSame($reason->value, $this->rowOf($current->record->getKey())->revoked_reason);
        self::assertNull($this->rowOf($other->record->getKey())->revoked_at);
        self::assertSame([SessionRevoked::class], $this->recordedClasses());

        $event = $this->recordedEvent(SessionRevoked::class);

        self::assertSame($reason, $event->reason);
        self::assertSame($current->record->getKey(), $event->context->sessionId);
        self::assertSame(IdentifierCoercion::stringify($current->record->getAttribute('principal_id')), $event->context->principalId);
    }

    /**
     * Rows of `[write to the current session during the change, status,
     * recorded reason]`.
     *
     * @return iterable<string, array{0: array<string, ?string>, 1: \SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus, 2: string}>
     */
    public static function provideWritesDuringTheChangesJudgement(): iterable
    {
        yield 'its refresh token rotated' => [['refresh_key' => str_repeat('0', 64)], FactorChangeStatus::REVOKED, 'factor_changed'];
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'signed_out', 'refresh_key' => null], FactorChangeStatus::SKIPPED, 'signed_out'];
    }

    /**
     * A current session written during the change's judgement is never left
     * active.
     *
     * @param  array<string, ?string>  $write
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus  $status
     * @param  string  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideWritesDuringTheChangesJudgement')]
    public function testACurrentSessionWrittenDuringTheChangesJudgementIsNeverLeftActive(array $write, FactorChangeStatus $status, string $reason): void
    {
        $current = $this->signedIn();
        $key     = $current->record->getKey();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, self::writingCheck($key, $write));

        $this->recordEvents([SessionRevoked::class, SessionReturnedToPending::class]);

        $result = Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertSame($status, $result->status);
        self::assertNull($result->credential);
        self::assertSame($reason, $this->rowOf($key)->revoked_reason);
        self::assertSame('active', $this->rowOf($key)->status);
        self::assertSame($status === FactorChangeStatus::REVOKED ? [SessionRevoked::class] : [], $this->recordedClasses());
    }

    /**
     * Rows of what made the current session other than live and active
     * meanwhile.
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): void}>
     */
    public static function provideSessionsTheChangeSkips(): iterable
    {
        yield from self::provideEndedSessions();

        yield 'pending and live' => [static function (SignedInSession $current): void {
            Session::query()->whereKey($current->record->getKey())->update(['status' => 'pending']);
        }];
    }

    /**
     * A current session that is no longer live and active is skipped.
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): void  $meanwhile
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSessionsTheChangeSkips')]
    public function testACurrentSessionThatIsNoLongerLiveAndActiveIsSkipped(\Closure $meanwhile): void
    {
        $current = $this->signedIn();

        $this->stepUp($current, 'factor-a');

        $meanwhile($current);

        $during = $this->columnsOf($current->record->getKey());

        $this->requireAFurtherFactor();
        $this->recordEvents([SessionRevoked::class, SessionReturnedToPending::class]);

        $result = Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertTrue($result->isSkipped());
        self::assertNull($result->pending);
        self::assertNull($result->credential);
        self::assertSame($during, $this->columnsOf($current->record->getKey()));
        self::assertSame(['factor-a' => null], $this->voidedOn($current->record->getKey()));
        self::assertSame([], $this->recorded);
    }

    /**
     * Rows of a current session that is not one of the identity's on this
     * guard.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Feature\Sessions\FactorRevocationsTest): \SineMacula\Laravel\Authentication\Contracts\Session}>
     */
    public static function provideSessionsAChangeRefuses(): iterable
    {
        yield 'another identity\'s session' => [static fn (self $test): Session => $test->anotherIdentitysSession()];
        yield 'another guard\'s session' => [static fn (self $test): Session => $test->anotherGuardsSession()];
        yield 'a session of the guard that is not a model' => [static fn (self $test): EloquentSession => self::nonModelSession()];
    }

    /**
     * A change whose current session is not the identity's is refused before
     * any write.
     *
     * @param  \Closure(self): \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSessionsAChangeRefuses')]
    public function testAChangeWhoseCurrentSessionIsNotTheIdentitysIsRefusedBeforeAnythingIsWritten(\Closure $session): void
    {
        $current = $this->signedIn();
        $given   = $session($this);
        $before  = Session::query()->orderBy('id')->get()->map(static fn (Session $row): array => $row->getAttributes())->all();

        $this->requireAFurtherFactor();
        $this->recordEvents([SessionRevoked::class, SessionReturnedToPending::class]);

        try {
            Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $given);

            self::fail('Expected the change to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The current session of a factor\'s change must be a session of guard [api] that the identity owns.', $exception->getMessage());
        }

        self::assertSame($before, Session::query()->orderBy('id')->get()->map(static fn (Session $row): array => $row->getAttributes())->all());
        self::assertSame([], $this->recorded);
    }

    /**
     * An identity off the storage connection is accepted for a change.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityOffTheStorageConnectionIsAcceptedForAChange(): void
    {
        $current  = $this->signedIn();
        $identity = $current->identity;

        self::assertInstanceOf(IntegrationIdentity::class, $identity);

        $identity->setConnection('elsewhere');

        $this->requireAFurtherFactor();

        self::assertTrue(Auth::sessions('api')->factorChanged($identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record)->isPending());
        self::assertSame('pending', $this->rowOf($current->record->getKey())->status);
    }

    /**
     * The guard forgets a session returned to pending once the change commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardForgetsTheCurrentSessionOnceTheChangeCommits(): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        $this->requireAFurtherFactor();

        try {
            DB::transaction(static function () use ($current): void {

                self::assertTrue(Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record)->isPending());

                throw new \RuntimeException('rolled back');
            });
        } catch (\RuntimeException) {
            self::assertSame($current->record->getKey(), $guard->session()?->getSessionIdentifier());
            self::assertSame('active', $this->rowOf($current->record->getKey())->status);
        }

        DB::transaction(static function () use ($current, $guard): void {

            self::assertTrue(Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record)->isPending());
            self::assertNotNull($guard->session());
        });

        self::assertNull($guard->session());
        self::assertNull($guard->user());
    }

    /**
     * A current session the change revoked is forgotten by the guard bound to
     * it once the change commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardForgetsACurrentSessionTheChangeRevoked(): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        IntegrationIdentity::query()->update(['is_active' => false]);

        self::assertTrue(Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::OTHER, $current->record)->isRevoked());
        self::assertNull($guard->session());
    }

    /**
     * Rows of `[event whose listener throws, what makes the change end the
     * session]`.
     *
     * @return iterable<string, array{0: class-string, 1: \Closure(): void}>
     */
    public static function provideEndingsOfTheCurrentSession(): iterable
    {
        yield 'returned to pending' => [SessionReturnedToPending::class, static function (): void {
            app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
            app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);
        }];

        yield 'revoked' => [SessionRevoked::class, static function (): void {
            IntegrationIdentity::query()->update(['is_active' => false]);
        }];
    }

    /**
     * A listener that throws leaves the guard unbound from a session the change
     * ended.
     *
     * @param  class-string  $event
     * @param  \Closure(): void  $ending
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideEndingsOfTheCurrentSession')]
    public function testAListenerThatThrowsLeavesTheGuardUnboundFromTheCurrentSessionTheChangeEnded(string $event, \Closure $ending): void
    {
        $current = $this->signedIn();
        $guard   = $this->boundGuard($current);

        $ending();

        Event::listen($event, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        $change = static fn (): FactorChangeResult => Auth::sessions('api')->factorChanged($current->identity, FactorChangeMade::FACTOR_CONFIRMED, $current->record);

        self::assertSame('listener failed', self::failureOf($change));
        self::assertNull($guard->session());
    }

    /**
     * A change after a removal in the same second finds what the removal left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeAfterARemovalInTheSameSecondFindsWhatTheRemovalLeft(): void
    {
        $this->requireAFurtherFactor();

        $returned = $this->satisfied('factor-a');
        $revoked  = $this->satisfied('factor-a', email: 'alan@example.test');
        $kept     = $this->satisfied('factor-a', email: 'grace@example.test');

        $this->stepUp($kept, 'factor-b');

        [$removal, $change] = DB::transaction(static fn (): array => [
            Auth::sessions('api')->factorRemoved($returned->identity, 'factor-a', $returned->record),
            Auth::sessions('api')->factorChanged($returned->identity, FactorChangeMade::FACTOR_REMOVED, $returned->record),
        ]);

        self::assertTrue($removal->isPending());
        self::assertTrue($change->isSkipped());
        self::assertNotNull($removal->credential);

        $proof = $this->proof($returned->identity, $returned->record->getKey(), 'factor-b', Purpose::SIGN_IN);

        self::assertTrue($this->sessions()->satisfy($removal->credential, $proof, self::requestClient())->isSignedIn());

        IntegrationIdentity::query()->where('email', 'alan@example.test')->update(['is_active' => false]);

        [$removal, $change] = DB::transaction(static fn (): array => [
            Auth::sessions('api')->factorRemoved($revoked->identity, 'factor-a', $revoked->record),
            Auth::sessions('api')->factorChanged($revoked->identity, FactorChangeMade::FACTOR_REMOVED, $revoked->record),
        ]);

        self::assertTrue($removal->currentRevoked);
        self::assertTrue($change->isSkipped());
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($revoked->record->getKey())->revoked_reason);

        [$removal, $change] = DB::transaction(static fn (): array => [
            Auth::sessions('api')->factorRemoved($kept->identity, 'factor-a', $kept->record),
            Auth::sessions('api')->factorChanged($kept->identity, FactorChangeMade::FACTOR_REMOVED, $kept->record),
        ]);

        self::assertFalse($removal->isPending());
        self::assertTrue($change->isActive());
        self::assertSame('active', $this->rowOf($kept->record->getKey())->status);
    }

    /**
     * A change a second after a removal returns a session the removal kept to
     * pending.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeAfterARemovalASecondLaterReturnsASessionTheRemovalKeptToPending(): void
    {
        app()->instance(AdditionalFactorPolicy::class, new readonly class implements AdditionalFactorPolicy {
            /**
             * Ask for a further factor within a minute.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return new Requirement(new RequirementPart(60));
            }
        });
        app()->instance(RequirementCheck::class, new readonly class implements RequirementCheck {
            /**
             * Meet the requirement with a further factor made less than its
             * maximum age before the time it is judged at.
             *
             * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
             * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
             * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
             *
             * @throws \InvalidArgumentException
             */
            #[\Override]
            public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
            {
                $since = $subject->now->subSeconds((int) $requirement->additionalVerification?->maxAgeSeconds - 1);

                return new RequirementEvaluation($subject->proofs($since, [ProofKind::ADDITIONAL_FACTOR], 1) === [] ? $requirement->kinds() : []);
            }
        });

        $kept = $this->satisfied('factor-a');

        $this->stepUp($kept, 'factor-b');
        $this->clockAt($this->now->addSeconds(59));

        [$removal, $change] = DB::transaction(function () use ($kept): array {
            $removal = Auth::sessions('api')->factorRemoved($kept->identity, 'factor-a', $kept->record);

            $this->clockAt($this->now->addSeconds(60));

            return [$removal, Auth::sessions('api')->factorChanged($kept->identity, FactorChangeMade::FACTOR_REMOVED, $kept->record)];
        });

        self::assertFalse($removal->isPending());
        self::assertNull($removal->credential);
        self::assertTrue($change->isPending());
        self::assertNotNull($change->credential);
        self::assertSame('pending', $this->rowOf($kept->record->getKey())->status);

        $proof = $this->proof($kept->identity, $kept->record->getKey(), 'factor-b', Purpose::SIGN_IN);

        self::assertTrue($this->sessions()->satisfy($change->credential, $proof, self::requestClient())->isSignedIn());
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

        $result = $this->sessions()->signIn('password', self::credentials('grace@example.test'), self::requestContext());

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
        $result = $this->sessions('admin')->signIn('password', self::credentials(), self::requestContext());

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
     * A session that declares the Eloquent session contract without being a
     * model.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private static function nonModelSession(): EloquentSession
    {
        $session = \Mockery::mock(StubNonModelSession::class);

        $session->shouldReceive('getGuard')->andReturn('api');

        return $session;
    }

    /**
     * A requirement check that writes the columns to the session's row, then
     * finds it unmet.
     *
     * @param  mixed  $key
     * @param  array<string, ?string>  $write
     * @return \SineMacula\Laravel\Authentication\Contracts\RequirementCheck
     */
    private static function writingCheck(mixed $key, array $write): RequirementCheck
    {
        return new readonly class ($key, $write) implements RequirementCheck {
            /**
             * Constructor.
             *
             * @param  mixed  $key
             * @param  array<string, ?string>  $write
             */
            public function __construct(

                /** The key of the session whose row is written. */
                private mixed $key,

                /** The columns written. */
                private array $write,
            ) {}

            /**
             * Write the session's row, then find the requirement unmet.
             *
             * @param  \SineMacula\Laravel\Authentication\Requirements\RequirementSubject  $subject
             * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
             * @return \SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation
             */
            #[\Override]
            public function evaluate(RequirementSubject $subject, Requirement $requirement): RequirementEvaluation
            {
                DB::table('authentication_sessions')->where('id', $this->key)->update($this->write);

                return new RequirementEvaluation($requirement->kinds());
            }
        };
    }

    /**
     * A session the identity with the email signed in to with its password now.
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

        $session = $this->sessions($guard)->signIn('password', self::credentials($email), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Ask every sign-in of the identity for a further factor.
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
     * it.
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

        $pending = $this->sessions($guard)->signIn('password', self::credentials($email), self::requestContext());

        self::assertTrue($pending->isPending());
        self::assertNotNull($pending->pending);
        self::assertNotNull($pending->credential);

        $result = Auth::sessions($guard)->satisfy(
            $pending->credential,
            $this->proof($pending->pending->identity, $pending->pending->id, $factor, Purpose::SIGN_IN, $guard),
            self::requestClient(),
        );

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

        self::assertTrue(
            $this->sessions($guard)->stepUp($this->proof($signedIn->identity, $signedIn->record->getKey(), $factor, Purpose::STEP_UP, $guard), self::requestClient())->isIssued(),
        );
    }

    /**
     * An accepted further factor's proof, made now, for the session and purpose
     * given.
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
     * Make every `SessionRevoked` listener throw.
     *
     * @return void
     */
    private function throwOnRevocation(): void
    {
        Event::listen(SessionRevoked::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });
    }

    /**
     * Run the change, expecting a listener to throw, and return the exception's
     * message.
     *
     * @param  \Closure(): mixed  $change
     * @return string
     */
    private static function failureOf(\Closure $change): string
    {
        try {
            $change();
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
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
     * When each of the session's factor proofs was voided, by factor, or
     * `null`.
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
