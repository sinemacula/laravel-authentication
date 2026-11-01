<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AccessOnlyIdentity;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\Integration\Fixtures\ForeignModelSessionsIdentity;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * Feature tests of the session service's sign-out and revocation methods: what
 * each revokes, what it leaves alone, what it reports, and the cutoff and
 * pending sessions a bulk revocation ends with the others.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(RevocationWriter::class)]
#[CoversClass(RevocationScope::class)]
#[CoversClass(IdentitySessions::class)]
#[CoversClass(AbstractGuard::class)]
#[CoversClass(SessionRevocations::class)]
#[CoversTrait(EndsSessions::class)]
final class RevocationWriterTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));
        Carbon::setTestNow(Carbon::parse(self::NOW));

        JWT::$timestamp = CarbonImmutable::parse(self::NOW)->getTimestamp();

        $this->createSessionTables();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();
        Carbon::setTestNow();

        JWT::$timestamp = null;

        Schema::dropIfExists('cutoff_identities');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Signing out a guest request does nothing and reports nothing.
     *
     * @return void
     */
    public function testSigningOutAGuestDoesNothing(): void
    {
        $this->recordEvents([SessionRevoked::class, Logout::class]);

        self::assertFalse($this->sessions()->signOut());
        self::assertSame([], $this->recorded);
    }

    /**
     * An access-only token, which names no stored session, is only forgotten:
     * `Logout` fires, nothing is revoked, and the guard stays signed out for
     * the rest of the request even though the request carries a credential.
     *
     * @return void
     */
    public function testASessionWithoutAPersistedSessionIsOnlyForgotten(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();
        $guard    = $this->freshGuard();

        $guard->setRequest(Request::create('/', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken]));
        $guard->login($identity, $identity, new PlainSessionFixture('plain-session'));

        $this->recordEvents([SessionRevoked::class, Logout::class]);

        self::assertFalse(self::sessionsOf($guard)->signOut());
        self::assertSame([Logout::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
        self::assertNull($guard->session());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * Signing out revokes the bound session once: a second sign-out on a
     * request bound to the same, already revoked session reports nothing more.
     *
     * @return void
     */
    public function testSigningOutRevokesTheBoundSessionOnce(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        $guard = $this->freshGuard();
        $guard->login($identity, $identity, $session->record);

        $this->recordEvents([SessionRevoked::class]);

        self::assertTrue(self::sessionsOf($guard)->signOut());

        $guard->login($identity, $identity, $session->record);

        self::assertFalse(self::sessionsOf($guard)->signOut());
        self::assertCount(1, $this->recorded);
        self::assertSame(self::NOW, DB::table('authentication_sessions')->value('revoked_at'));
    }

    /**
     * Signing out reports the tenant the bound principal acts within, and none
     * when that tenant can no longer be loaded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutReportsTheBoundTenantWhenItLoads(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $loaded = $membership;

        $this->recordEvents([SessionRevoked::class]);

        foreach ([true, false] as $loads) {

            $session = $this->signIn('members', 'member@example.test');
            $guard   = $this->freshGuard('members');

            if (!$loads) {
                $tenant->delete();
                $membership = ActivatableTenantMembership::query()->findOrFail($membership->getKey());
            }

            $guard->login($member, $membership, $session->record);

            self::assertTrue(self::sessionsOf($guard)->signOut());
        }

        [$loading, $unloadable] = $this->recorded;

        self::assertInstanceOf(SessionRevoked::class, $loading);
        self::assertInstanceOf(SessionRevoked::class, $unloadable);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $loading->context->tenantId);
        self::assertSame($loaded, $loading->context->principal);
        self::assertNull($unloadable->context->tenant);
    }

    /**
     * IdentitySessions is a static utility; instantiation is disallowed through
     * the private constructor. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testIdentitySessionsCannotBeInstantiated(): void
    {
        $reflection  = new \ReflectionClass(IdentitySessions::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * A bound session that is not an Eloquent model has nothing to revoke: the
     * guard only forgets it, and the session is never asked anything.
     *
     * @return void
     */
    public function testABoundSessionThatIsNotAModelIsOnlyForgotten(): void
    {
        $identity = $this->seedIdentity();
        $record   = \Mockery::mock(EloquentSession::class);
        $guard    = $this->freshGuard();

        $record->shouldReceive('getSignInMethod')->andReturn('password');
        $record->shouldReceive('getSessionIdentifier')->andReturn('mocked-session');
        $record->shouldNotReceive('getGuard');

        $guard->login($identity, $identity, $record);

        self::assertFalse(self::sessionsOf($guard)->signOut());
        self::assertTrue($guard->guest());
    }

    /**
     * Signing out everywhere revokes the request's own session too unless asked
     * to keep it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutEverywhereRevokesTheCurrentSessionByDefault(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();
        $guard    = $this->freshGuard();

        $guard->login($identity, $identity, $session->record);

        self::assertSame(1, self::sessionsOf($guard)->signOutEverywhere());
        self::assertSame(self::NOW, self::revokedAt($session));
    }

    /**
     * An identity whose key is unknown, as an unsaved model's, owns no pending
     * session, so none is ended for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutAKeyEndsNoPendingSession(): void
    {
        $this->seedIdentity();

        [$pending] = $this->pendingSignIn();

        self::assertSame(0, $this->sessions()->revokeSessions(new IntegrationIdentity, RevocationReason::REVOKED));
        self::assertNull(DB::table('authentication_sessions')->where('id', $pending)->value('revoked_at'));
    }

    /**
     * A scope picks sessions by type as well as by identifier: another type's
     * rows with the same identifier, pending ones among them, are left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAScopeMatchesTheTypeAsWellAsTheIdentifier(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        $this->pendingSignIn();

        DB::table('authentication_sessions')->update(['authenticatable_type' => 'another_type', 'principal_type' => 'another_type']);

        $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED);
        $this->sessions()->revokePrincipalSessions($identity, RevocationReason::REVOKED);

        self::assertNull(self::revokedAt($session));
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * Signing out everywhere on a guest request revokes nothing.
     *
     * @return void
     */
    public function testSigningOutEverywhereAsAGuestRevokesNothing(): void
    {
        $this->seedIdentity();
        $this->signIn();

        self::assertSame(0, $this->sessions()->signOutEverywhere());
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
    }

    /**
     * Revoking an identity's sessions covers every guard, skips the excepted
     * session, leaves other identities' sessions alone, ends the identity's
     * pending session with the rest, so its credential can no longer activate
     * it, and reports each session and then the scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAnIdentitysSessionsEndsEverySessionButTheExcepted(): void
    {
        $identity = $this->seedIdentity();

        $this->seedIdentity('grace@example.test');

        $kept    = $this->signIn();
        $revoked = $this->signIn('admin');
        $theirs  = $this->signIn('api', 'grace@example.test');

        [$pending, $pendingCredential, $pendingProof] = $this->pendingSignIn();
        [, $theirsCredential, $theirsProof]           = $this->pendingSignIn('grace@example.test');

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(2, $this->sessions('api')->revokeSessions($identity, RevocationReason::PASSWORD_CHANGED, $kept->record));

        self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
        self::assertSame(
            [self::idOf($revoked), $pending],
            array_map(static fn (object $event): ?string => $event instanceof SessionRevoked ? $event->context->sessionId : null, array_slice($this->recorded, 0, 2)),
        );

        $record = $this->recorded[0];

        self::assertInstanceOf(SessionRevoked::class, $record);

        self::assertSame('admin', $record->context->guard);
        self::assertSame(self::idOf($revoked), $record->context->sessionId);
        self::assertSame($identity, $record->context->identity);
        self::assertNull($record->context->principal);
        self::assertSame($identity->getMorphClass(), $record->context->principalMorphClass);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $record->context->principalId);
        self::assertSame(RevocationReason::PASSWORD_CHANGED, $record->reason);

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame('api', $scope->context->guard);
        self::assertSame($identity, $scope->context->identity);
        self::assertSame(self::idOf($kept), $scope->context->sessionId);
        self::assertSame(1, $scope->revoked);
        self::assertNull($scope->tokensValidAfter);

        self::assertNull(self::revokedAt($kept));
        self::assertNull(self::revokedAt($theirs));
        self::assertSame(self::NOW, self::revokedAt($revoked));
        self::assertSame('password_changed', DB::table('authentication_sessions')->where('id', $pending)->value('revoked_reason'));
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->satisfy($pendingCredential, $pendingProof)->reason);
        self::assertTrue($this->sessions()->satisfy($theirsCredential, $theirsProof)->isSignedIn());
    }

    /**
     * An excepted session of another model is not a session of the scope, so
     * nothing is kept for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptedSessionOfAnotherModelKeepsNothing(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        self::assertSame(1, $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED, new PlainSessionFixture('plain-session')));
    }

    /**
     * A revocation of several scopes counts every scope's revoked sessions, and
     * reports each scope with its own count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSeveralScopesCountEveryScopesSessions(): void
    {
        [, $first, $tenant] = $this->seedMember();
        [, $second]         = $this->seedMember('other@example.test', $tenant);

        $this->signIn('members', 'member@example.test');
        $this->signIn('members', 'member@example.test');
        $this->signIn('members', 'other@example.test');

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(3, $this->sessions('members')->tenantDeactivated($tenant, [$first, $second]));
        self::assertSame([2, 1], array_map(static fn (object $event): int => $event instanceof SignedOutEverywhere ? $event->revoked : -1, $this->recorded));
    }

    /**
     * A bulk revocation deletes the pending identifier changes its identity
     * scopes name, in the same transaction as their sessions, and no other: a
     * principal's scope names none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationDeletesThePendingChangesItsScopesName(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $keys     = [PendingChanges::key($identity, 'email'), PendingChanges::key($identity, 'phone'), PendingChanges::key($other, 'email')];

        foreach ($keys as $index => $key) {
            DB::table('identifier_changes')->insert([
                'id'           => $key,
                'guard'        => 'api',
                'type'         => 'email',
                'previous'     => null,
                'identifier'   => "new{$index}@example.test",
                'request_id'   => "0195f4a2-7b1c-4000-8000-00000000000{$index}",
                'requested_at' => self::NOW,
                'expires_at'   => self::NOW,
            ]);
        }

        $revocations = new RevocationWriter(app('db'), static fn (): mixed => null);
        $none        = static function (): void {};

        $revocations->revokeScopes([RevocationScope::principal($identity)], RevocationReason::REVOKED, null, CarbonImmutable::now(), $none, $none);

        self::assertSame(3, DB::table('identifier_changes')->count());

        $revocations->revokeScopes([RevocationScope::identity($identity, ['email', 'phone'])], RevocationReason::REVOKED, null, CarbonImmutable::now(), $none, $none);

        self::assertSame([$keys[2]], DB::table('identifier_changes')->pluck('id')->all());
    }

    /**
     * A bulk revocation with nothing left to revoke is still reported, with a
     * count of none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationOfNothingIsStillReported(): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(0, $this->sessions()->revokeSessions($identity, RevocationReason::REVOKED));
        self::assertSame([SignedOutEverywhere::class], $this->recordedClasses());
        self::assertSame(0, $this->recordedEvent(SignedOutEverywhere::class)->revoked);
    }

    /**
     * An identity that cannot hold sessions cannot hold a pending one either
     * (no session starts for it), so its revocation leaves the session table
     * alone, a pending row recorded for it by hand included, and is still
     * reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutSessionsLeavesThePackagesTablesAlone(): void
    {
        Schema::create('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->timestamps();
        });

        $identity = new AccessOnlyIdentity;
        $identity->forceFill(['email' => 'ada@example.test'])->save();

        DB::table('authentication_sessions')->insert([
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'signed_in_at'         => now(),
            'idle_expires_at'      => now()->addMinutes(5),
            'id'                   => '0190e1a4-0000-7000-8000-000000000001',
            'generation'           => '0190e1a4-0000-7000-8000-000000000002',
            'status'               => 'pending',
            'requires'             => '["mfa"]',
            'pending_key'          => str_repeat('a', 64),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()) ?? '',
        ]);

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(0, $this->sessions()->revokeSessions($identity, RevocationReason::IDENTITY_DEACTIVATED));
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertCount(1, $this->recorded);

        Schema::drop('access_only_identities');
    }

    /**
     * An identity that holds no sessions has none to revoke one of.
     *
     * @return void
     */
    public function testAnIdentityWithoutSessionsHasNoneToRevoke(): void
    {
        self::assertFalse($this->sessions()->revokeSession(new AccessOnlyIdentity, '0190e1a4-0000-7000-8000-000000000000', RevocationReason::REVOKED));
    }

    /**
     * A misconfigured `sessions()` relation over a model that is not a session
     * is refused before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesASessionsRelationOverAnotherModel(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The sessions() relation of ' . ForeignModelSessionsIdentity::class . ' must query a model that implements');

        $this->sessions()->revokeSessions(new ForeignModelSessionsIdentity, RevocationReason::REVOKED);
    }

    /**
     * Revoking a principal's sessions revokes only the sessions acting as it,
     * of every identity, pending ones included.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAPrincipalsSessionsEndsOnlyItsSessions(): void
    {
        [, $membership, $tenant] = $this->seedMember();
        [, $otherMembership]     = $this->seedMember('other@example.test', $tenant);

        $mine   = $this->signIn('members', 'member@example.test');
        $theirs = $this->signIn('members', 'other@example.test');

        $this->recordEvents([SessionRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(1, $this->sessions('members')->revokePrincipalSessions($membership, RevocationReason::PRINCIPAL_DEACTIVATED));

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame($membership, $scope->context->principal);
        self::assertInstanceOf(ActivatableTenantMember::class, $scope->context->identity);
        self::assertSame(IdentifierCoercion::stringify($membership->identity_id), $scope->context->identityId);
        self::assertSame($membership, $this->recordedEvent(SessionRevoked::class)->context->principal);
        self::assertSame($scope->context->identity, $this->recordedEvent(SessionRevoked::class)->context->identity);
        self::assertSame(self::NOW, self::revokedAt($mine));
        self::assertNull(self::revokedAt($theirs));
        self::assertSame(IdentifierCoercion::stringify($otherMembership->getKey()), DB::table('authentication_sessions')->whereNull('revoked_at')->value('principal_id'));
    }

    /**
     * An unsaved principal records no sessions: nothing is revoked, and a
     * session that records no principal is not taken for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnsavedPrincipalRevokesNothing(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        DB::table('authentication_sessions')->update(['principal_type' => null, 'principal_id' => null]);

        self::assertSame(0, $this->sessions()->revokePrincipalSessions(new ActivatableTenantMembership, RevocationReason::REVOKED));
        self::assertNull(self::revokedAt($session));
    }

    /**
     * A scope that records a "tokens valid after" cutoff has it moved to the
     * revocation's second, which the event reports; a second revocation in the
     * same second moves nothing and reports none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMovesTheScopesCutoffAndReportsIt(): void
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => 'ada@example.test'])->save();
        $identity = CutoffIdentity::query()->findOrFail($identity->id);

        $this->recordEvents([SignedOutEverywhere::class]);

        $this->sessions()->revokeSessions($identity, RevocationReason::SIGNED_OUT_EVERYWHERE);
        $this->sessions()->revokeSessions($identity, RevocationReason::SIGNED_OUT_EVERYWHERE);

        self::assertSame(self::NOW, DB::table('cutoff_identities')->value('tokens_valid_after'));
        [$first, $second] = $this->recorded;

        self::assertInstanceOf(SignedOutEverywhere::class, $first);
        self::assertInstanceOf(SignedOutEverywhere::class, $second);
        self::assertSame(self::NOW, $first->tokensValidAfter?->format('Y-m-d H:i:s'));
        self::assertNull($second->tokensValidAfter);
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign the identity with the email in on the guard.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Sign the identity with the email in while every sign-in needs a further
     * factor, and return its pending session's id, its credential, and an
     * accepted further factor's proof bound to it.
     *
     * @param  string  $email
     * @return array{0: string, 1: string, 2: \SineMacula\Laravel\Authentication\Proofs\ProofResult}
     *
     * @throws \Throwable
     */
    private function pendingSignIn(string $email = 'ada@example.test'): array
    {
        $previous = app(AdditionalFactorPolicy::class);

        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });

        $result = $this->sessions()->signIn('password', self::credentials($email));

        app()->instance(AdditionalFactorPolicy::class, $previous);

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        $id = (string) IdentifierCoercion::stringify($result->pending->id);

        return [$id, $result->credential, self::adapterProof($result->pending->identity, 'api', $result->pending->id, Purpose::SIGN_IN)];
    }

    /**
     * The identifier of the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function idOf(SignedInSession $session): string
    {
        return (string) IdentifierCoercion::stringify($session->record->getSessionIdentifier());
    }

    /**
     * When the session was revoked, as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return mixed
     */
    private static function revokedAt(SignedInSession $session): mixed
    {
        return DB::table('authentication_sessions')->where('id', self::idOf($session))->value('revoked_at');
    }
}
