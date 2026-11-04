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
 * Feature tests of the mandatory triggers the factor package calls, through the
 * session service against a real database: a factor's removal ends the
 * identity's other sessions and judges the current one again without the
 * factor, voiding only that session's proofs made with it, keeping it, taking
 * it back to pending or revoking it; a reset ends every session; a removed
 * first-factor credential voids nothing; and an addition, a change of the
 * factor package's that removes no factor, judges the current session again the
 * same way, voiding nothing and touching no other session.
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
    use InspectsIssuanceGuards, InteractsWithSessions;

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
     * with the removed factor are voided, after its issuance guard is written,
     * another factor's stay, and the other sessions' proofs are left as they
     * are, as are their guards.
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
     * Rows of `[what is written to the current session's row while the removal
     * judges it, whether the removal's own revocation ends it]`.
     *
     * @return iterable<string, array{0: array<string, ?string>, 1: bool}>
     */
    public static function provideWritesDuringTheJudgement(): iterable
    {
        yield 'its refresh token rotated' => [['refresh_key' => str_repeat('0', 64)], true];
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'signed_out', 'refresh_key' => null], false];
    }

    /**
     * A current session whose row is written while the removal judges it short
     * of a further factor (here by a check that writes it inside the removal's
     * transaction) is never left active: the return to pending misses its
     * compare-and-swap, so the removal revokes it as `factor_removed`, and
     * counts it only when that revocation was its own.
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
     * and counted, and its revocation reported with the principal the session
     * records.
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
     * its issuance guard written and its proofs made with the removed factor
     * voided, another factor's kept, and stays pending as it was: nothing else
     * of it is written, judged or counted.
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
     * A current session that stays active once its proofs made with the factor
     * are voided has the context of the guard bound to it forgotten at once:
     * the rest of the caller's transaction no longer holds the further factor.
     * A rollback forgets it again, so the context holds the factor once more;
     * once the removal commits, the context still lacks it and the session
     * stays bound.
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
        yield 'a session of the guard that is not a model' => [static fn (self $test, SignedInSession $current): array => ['factor-a', self::nonModelSession()], $session];
    }

    /**
     * A removal whose factor names nothing, or whose current session is not one
     * of the identity's stored sessions on this guard, is refused before
     * anything is written or reported.
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
     * Rows of `[a change that ends every session of the current session's
     * identity]`.
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
     * A `SessionRevoked` listener that throws once a change ending every
     * session of the identity commits cannot leave the guard bound to the
     * identity: the binding is forgotten before any session is reported.
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
     * A `SessionRevoked` listener that throws on the other session a removal
     * ended (here one still pending) cannot leave the guard bound to the
     * current session the removal returned to pending: the binding is forgotten
     * before any session is reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAListenerThatThrowsLeavesTheGuardUnboundFromACurrentSessionReturnedToPending(): void
    {
        $this->requireAFurtherFactor();

        $current = $this->satisfied('factor-a');
        $other   = $this->sessions()->signIn('password', self::credentials())->pending;
        $guard   = $this->boundGuard($current);

        self::assertNotNull($other);

        $this->throwOnRevocation();

        self::assertSame('listener failed', self::failureOf(static fn (): FactorRemoval => Auth::sessions('api')->factorRemoved($current->identity, 'factor-a', $current->record)));
        self::assertNull($guard->session());
        self::assertSame('pending', $this->rowOf($current->record->getKey())->status);
        self::assertSame(RevocationReason::FACTOR_REMOVED->value, $this->rowOf($other->id)->revoked_reason);
    }

    /**
     * A `SessionRevoked` listener that throws on the current session a removal
     * revoked cannot leave the guard bound to it: the binding is forgotten
     * before the session is reported.
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
     * A change of the factor package's that leaves an active current session
     * short of a further factor (here its identity's first factor confirmed,
     * which the factor policy now asks for) returns it to pending: its access
     * and refresh tokens stop at once, `SessionReturnedToPending` reports the
     * `factor_change` flow, and its new pending credential takes a further
     * factor that activates it again under the same key.
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
        self::assertFalse($this->sessions()->refresh((string) $current->tokens->refreshToken?->reveal())->isRefreshed());

        $again = $this->sessions()->satisfy($change->credential, $this->proof($current->identity, $current->record->getKey(), 'factor-a', Purpose::SIGN_IN));

        self::assertTrue($again->isSignedIn());
        self::assertSame($current->record->getKey(), $again->session?->record->getKey());
        self::assertSame('active', $this->rowOf($current->record->getKey())->status);
    }

    /**
     * The tenant's further factor is judged after a change too: a session its
     * tenant let in on its password alone, whose tenant now asks for a further
     * factor, returns to pending, recording the version the tenant answers now.
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
     * Rows of `[the change made]`: every change the factor package names.
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
     * Whatever the change, a current session it leaves short returns to pending
     * in the same way, and nothing else is written or reported: the identity's
     * other sessions, active or pending, keep their rows (status, digests,
     * issuance guards), its pending identifier changes are kept, its own row is
     * left as it was, and no proof is voided.
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

        $pending = $this->sessions()->signIn('password', self::credentials())->pending;

        self::assertNotNull($pending);

        DB::table('identifier_changes')->insert([
            'id'           => 'change-1',
            'guard'        => 'api',
            'type'         => 'email',
            'previous'     => null,
            'identifier'   => 'ada@new.example.test',
            'request_id'   => 'request-1',
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
        self::assertSame(['change-1'], DB::table('identifier_changes')->pluck('id')->all());
        self::assertSame(['factor-a' => null], $this->voidedOn($other->record->getKey()));
        self::assertSame(0, Session::query()->whereNotNull('revoked_at')->count());
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
    }

    /**
     * A current session that still meets what it is asked stays active: only
     * its issuance guard is written, before anything reads its proofs; no proof
     * is voided, nothing is reported, its tokens keep working, and the guard
     * bound to it stays bound with the authentication context it held.
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
     * Rows of `[guard, email, what happened to the session meanwhile, the
     * change made, the reason its revocation records]`: each session no longer
     * admitted, after a change other than a removal and after a removal.
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
     * A current session that is no longer admitted as a refresh admits it, or
     * whose tenant now requires a connection, is revoked by the change, with
     * `factor_removed` after a removal and `factor_changed` after any other
     * change, stored on its row and reported once with the principal it
     * records; the identity's other session is left as it is.
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
     * Rows of `[what is written to the current session's row while the change
     * judges it, the status answered, the reason its row records]`.
     *
     * @return iterable<string, array{0: array<string, ?string>, 1: \SineMacula\Laravel\Authentication\Sessions\Enums\FactorChangeStatus, 2: string}>
     */
    public static function provideWritesDuringTheChangesJudgement(): iterable
    {
        yield 'its refresh token rotated' => [['refresh_key' => str_repeat('0', 64)], FactorChangeStatus::REVOKED, 'factor_changed'];
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'signed_out', 'refresh_key' => null], FactorChangeStatus::SKIPPED, 'signed_out'];
    }

    /**
     * A current session whose row is written while the change judges it short
     * of a further factor is never left active: the return to pending misses
     * its compare-and-swap, so the change revokes it as `factor_changed` and
     * answers `revoked`, or, when another writer had revoked it meanwhile,
     * keeps that revocation, reports none of its own and answers `skipped`.
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
     * Rows of `[what made the current session other than a live, active session
     * of the identity meanwhile]`: each ended session, and a live pending one.
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
     * A current session that has meanwhile been revoked, ended, replaced or
     * returned to pending is skipped: its row, issuance guard and proofs are
     * left as they are, and nothing is reported; a pending one is judged at its
     * next action instead.
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
     * Rows of `[the current session given]`: one that is not one of the
     * identity's stored sessions on this guard.
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
     * A change whose current session is not one of the identity's stored
     * sessions on this guard is refused, naming the change, before anything is
     * written or reported.
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
     * An identity that does not live on the storage connection is accepted: a
     * change writes nothing of the identity, so only its session is judged.
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
     * The guard bound to the current session forgets it once the change that
     * returned it to pending commits, not before; a change rolled back keeps it
     * bound and the session active.
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
     * Rows of `[the event whose listener throws, what makes the change end the
     * current session]`.
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
     * A listener that throws on the report of the current session the change
     * returned to pending or revoked cannot leave the guard bound to it: the
     * binding is forgotten before the session is reported.
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
     * Called after `factorRemoved()` in the same change and the same second, a
     * session the removal returned to pending is skipped, its pending
     * credential (the removal's) still taking a further factor; one the removal
     * revoked is skipped too; one the removal kept is judged again on the same
     * proofs and stays active.
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

        self::assertTrue($this->sessions()->satisfy($removal->credential, $proof)->isSignedIn());

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
     * Called after `factorRemoved()` in the same change but a second later, a
     * session the removal kept is judged at the change's own time: the proof
     * that met a further factor's maximum age at the removal no longer does, so
     * it returns to pending, its credential only on the change's result.
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

        self::assertTrue($this->sessions()->satisfy($change->credential, $proof)->isSignedIn());
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
     * A session of the `api` guard that declares the Eloquent session contract
     * without being an Eloquent model.
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
     * A requirement check that writes the columns given to the row of the
     * session with the key given, then finds the requirement unmet.
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
