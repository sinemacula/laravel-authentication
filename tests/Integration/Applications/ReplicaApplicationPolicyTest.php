<?php

declare(strict_types = 1);

namespace Tests\Integration\Applications;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Admission\ApplicationAdmission;
use SineMacula\Laravel\Authentication\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Sessions\PendingEvaluation;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use Tests\Concerns\InteractsWithApplicationGrants;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Sessions\GrantedApplicationAccess;
use Tests\Fixtures\Sessions\GrantedApplicationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Tests that an application policy of the application's own is asked on the
 * write connection on every session path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationAdmission::class)]
#[CoversClass(SignInAdmission::class)]
#[CoversClass(RefreshAdmission::class)]
#[CoversClass(SessionSwitch::class)]
#[CoversClass(PendingEvaluation::class)]
final class ReplicaApplicationPolicyTest extends TestCase
{
    use InteractsWithApplicationGrants, InteractsWithLaggingReplica, InteractsWithSessions;

    /**
     * Create the tables on the primary and the replica, and bind the policy
     * that reads its own rows.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });

        $this->bindGrantedApplicationPolicy();
    }

    /**
     * Remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A password sign-in is admitted or refused as the primary holds the
     * verification and the grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInIsDecidedOnThePrimary(): void
    {
        $identity     = $this->seedIdentity();
        $verification = $this->verify($identity);
        $grant        = $this->grant($identity);

        self::assertTrue($this->freshGuard()->attempt(self::credentials()));

        $this->withdrawOnThePrimary(GrantedApplicationPolicy::VERIFICATIONS, $verification);
        $this->recordEvents([AuthenticationFailed::class]);

        self::assertFalse($this->freshGuard()->attempt(self::credentials()));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->recordedEvent(AuthenticationFailed::class)->reason);

        $this->verify($identity);
        $this->withdrawOnThePrimary(GrantedApplicationAccess::GRANTS, $grant);

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->sessions()->signIn('password', self::credentials(), self::requestContext())->reason);
    }

    /**
     * A started session is admitted or refused as the primary holds the grant.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStartedSessionIsDecidedOnThePrimary(): void
    {
        $identity = $this->seedIdentity();
        $grant    = $this->grant($identity);

        self::assertTrue($this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext())->isSignedIn());

        $this->withdrawOnThePrimary(GrantedApplicationAccess::GRANTS, $grant);

        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext())->reason);
    }

    /**
     * A refresh is admitted or refused as the primary holds the grant, without
     * revoking the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshIsDecidedOnThePrimary(): void
    {
        $identity = $this->seedIdentity();
        $grant    = $this->grant($identity);

        $this->verify($identity);

        $refreshed = $this->sessions()->refresh(self::bodyToken($this->signIn('api', 'ada@example.test')->tokens), self::requestClient());

        self::assertNotNull($refreshed->session);

        $this->withdrawOnThePrimary(GrantedApplicationAccess::GRANTS, $grant);

        self::assertSame(
            FailureReason::PRINCIPAL_INELIGIBLE,
            $this->sessions()->refresh(self::bodyToken($refreshed->session->tokens), self::requestClient())->reason,
        );
        self::assertNull(DB::table('authentication_sessions')->useWritePdo()->value('revoked_at'));
    }

    /**
     * A switch is admitted or refused as the primary holds the verification.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsDecidedOnThePrimary(): void
    {
        [$member, $first] = $this->seedMember();

        $other        = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second       = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $verification = $this->verify($member);

        $this->grant($first);
        $this->grant($second);

        $switched = $this->sessions('members')->switchTo(
            self::bodyToken($this->signIn('members', 'member@example.test', $first)->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertTrue($switched->isSwitched());
        self::assertNotNull($switched->session);

        $this->withdrawOnThePrimary(GrantedApplicationPolicy::VERIFICATIONS, $verification);

        $back = $this->sessions('members')->switchTo(
            self::bodyToken($switched->session->tokens),
            SwitchTarget::principal($first),
            self::requestClient(),
        );

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $back->reason);
    }

    /**
     * The principals offered are those the primary's verification and grant
     * admit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheChoicesAreDecidedOnThePrimary(): void
    {
        [$member, $first] = $this->seedMember();

        $second       = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $first->tenant_id]);
        $verification = $this->verify($member);
        $grant        = $this->grant($first);

        $this->grant($second);

        self::assertCount(2, $this->sessions('members')->principals($member, 'email'));

        $this->withdrawOnThePrimary(GrantedApplicationAccess::GRANTS, $grant);

        $principals = $this->sessions('members')->principals($member, 'email');

        self::assertCount(1, $principals);
        self::assertIsModel($second, $principals[0]);

        $this->withdrawOnThePrimary(GrantedApplicationPolicy::VERIFICATIONS, $verification);

        self::assertSame([], $this->sessions('members')->principals($member, 'email'));
    }

    /**
     * Configure the session guards over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureSessionGuards($config);

        $this->configureLaggingReplica($config);
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Sign in to the guard with the identity's password, as the principal named
     * if one is.
     *
     * @param  string  $guard
     * @param  string  $email
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(string $guard, string $email, ?Principal $principal = null): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email), SignInContext::fromRequest(request(), principal: $principal))->session;

        self::assertNotNull($session);

        return $session;
    }
}
