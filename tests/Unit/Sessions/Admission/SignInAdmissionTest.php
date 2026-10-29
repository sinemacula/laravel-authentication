<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Admission;

use Illuminate\Config\Repository;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\SignInAdmission;
use Tests\Unit\Stubs\StubVerifiableIdentity;

/**
 * Unit tests for the checks every sign-in passes once its identity is known:
 * their order, the reason each failure reports, and the context a refusal
 * carries.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInAdmission::class)]
final class SignInAdmissionTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\AudiencePolicy The guards' audience policy. */
    private MockInterface $audience;

    /**
     * Build a fresh audience policy mock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->audience = \Mockery::mock(AudiencePolicy::class);

        $this->audience->shouldReceive('admitIdentifier')->byDefault()->andReturnNull();
    }

    /**
     * An active identity, principal and tenant the audience policy admits are
     * admitted together, and the policy is asked with the guard and the
     * identifier type.
     *
     * @return void
     */
    public function testAdmitsWhenEveryCheckPasses(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $tenant    = $this->tenant(true);
        $principal = $this->principal(true, $tenant);

        $this->audience->shouldReceive('admitIdentifier')->once()->with('api', $identity, 'email')->andReturnNull();
        $this->audience->shouldReceive('admit')->once()->with('api', $identity, $principal, 'email')->andReturnNull();

        $admitted = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertInstanceOf(AdmittedSignIn::class, $admitted);
        self::assertSame($identity, $admitted->identity);
        self::assertSame($principal, $admitted->principal);
        self::assertSame($tenant, $admitted->tenant);
    }

    /**
     * An inactive identity is refused before its principal is resolved, so the
     * resolver never runs for it.
     *
     * @return void
     */
    public function testRefusesAnInactiveIdentityWithoutResolvingAPrincipal(): void
    {
        $identity = $this->inactiveIdentity();
        $resolved = false;

        $this->audience->shouldNotReceive('admitIdentifier');
        $this->audience->shouldNotReceive('admit');

        $refused = $this->admission()->admit('api', $identity, static function () use (&$resolved): ?Principal {
            $resolved = true;

            return null;
        }, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertFalse($resolved);
        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::IDENTITY_INACTIVE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertNull($refused->principal);
    }

    /**
     * Whatever policy is bound, its refusal of the identity with the identifier
     * type comes before any principal is resolved, so the answer is the same
     * whether the identity has a principal or not, and the policy is never
     * asked about one.
     *
     * @return void
     */
    public function testAnyPolicysRefusalOfTheIdentityComesBeforeItsPrincipal(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $resolved = false;

        $this->audience->shouldReceive('admitIdentifier')->once()->with('api', $identity, 'phone')->andReturn(FailureReason::IDENTIFIER_UNVERIFIED);
        $this->audience->shouldNotReceive('admit');

        $refused = $this->admission()->admit('api', $identity, static function () use (&$resolved): ?Principal {
            $resolved = true;

            return null;
        }, FailureReason::PRINCIPAL_UNRESOLVED, 'phone');

        self::assertFalse($resolved);
        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertNull($refused->principal);
    }

    /**
     * With the package's policy and a guard that requires a verified
     * identifier, an identity whose identifier is unverified is refused as
     * `identifier_unverified` before its principal is resolved, so the answer
     * is the same whether it has a principal or not; a verified one goes on to
     * its principal, and a sign-in that used no identifier is not held to it.
     *
     * @return void
     */
    public function testThePackagePolicyRefusesAnUnverifiedIdentifierWithoutResolvingAPrincipal(): void
    {
        $admission  = new SignInAdmission($this->packagePolicy());
        $unverified = new StubVerifiableIdentity(1, ['email' => 'ben@example.com']);
        $resolved   = false;

        $refused = $admission->admit('api', $unverified, static function () use (&$resolved): ?Principal {
            $resolved = true;

            return null;
        }, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertFalse($resolved);
        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $refused->reason);
        self::assertSame($unverified, $refused->identity);
        self::assertNull($refused->principal);

        $unnamed = $admission->admit('api', $unverified, static fn (): ?Principal => null, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(RefusedSignIn::class, $unnamed);
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $unnamed->reason);

        $verified = new StubVerifiableIdentity(2, ['email' => 'ada@example.com']);
        $verified->markIdentifierAsVerified('email', 'ada@example.com');

        $afterGate = $admission->admit('api', $verified, static fn (): ?Principal => null, FailureReason::PRINCIPAL_UNRESOLVED, 'email');

        self::assertInstanceOf(RefusedSignIn::class, $afterGate);
        self::assertSame(FailureReason::PRINCIPAL_UNRESOLVED, $afterGate->reason);
    }

    /**
     * A principal that does not resolve is refused with the reason the caller
     * gave for it: unresolved for a default principal, a mismatch for a pinned
     * one.
     *
     * @return void
     */
    public function testRefusesAnUnresolvedPrincipalWithTheCallersReason(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $this->audience->shouldNotReceive('admit');

        foreach ([FailureReason::PRINCIPAL_UNRESOLVED, FailureReason::PRINCIPAL_MISMATCH] as $reason) {

            $refused = $this->admission()->admit('api', $identity, static fn (): ?Principal => null, $reason, null);

            self::assertInstanceOf(RefusedSignIn::class, $refused);
            self::assertSame($reason, $refused->reason);
            self::assertSame($identity, $refused->identity);
            self::assertNull($refused->principal);
        }
    }

    /**
     * An inactive principal is refused without its tenant being read.
     *
     * @return void
     */
    public function testRefusesAnInactivePrincipal(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('isActive')->once()->andReturnFalse();
        $principal->shouldNotReceive('getTenant');

        $this->audience->shouldNotReceive('admit');

        $refused = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::PRINCIPAL_INACTIVE, $refused->reason);
        self::assertSame($principal, $refused->principal);
        self::assertNull($refused->tenant);
    }

    /**
     * A principal whose tenant is inactive is refused, carrying the principal.
     *
     * @return void
     */
    public function testRefusesAPrincipalWhoseTenantIsInactive(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = $this->principal(true, $this->tenant(false));

        $this->audience->shouldNotReceive('admit');

        $refused = $this->admission()->admit('api', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::TENANT_INACTIVE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertSame($principal, $refused->principal);
        self::assertNull($refused->tenant);
    }

    /**
     * The audience policy's refusal is reported with its own reason and the
     * whole context: identity, principal and tenant.
     *
     * @return void
     */
    public function testRefusesWithTheAudiencePolicysReason(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $tenant    = \Mockery::mock(Tenant::class);
        $principal = $this->principal(true, $tenant);

        $this->audience->shouldReceive('admit')
            ->once()
            ->with('admin', $identity, $principal, null)
            ->andReturn(FailureReason::PRINCIPAL_INELIGIBLE);

        $refused = $this->admission()->admit('admin', $identity, static fn (): Principal => $principal, FailureReason::PRINCIPAL_UNRESOLVED, null);

        self::assertInstanceOf(RefusedSignIn::class, $refused);
        self::assertSame(FailureReason::PRINCIPAL_INELIGIBLE, $refused->reason);
        self::assertSame($identity, $refused->identity);
        self::assertSame($principal, $refused->principal);
        self::assertSame($tenant, $refused->tenant);
        self::assertNull($refused->device);
        self::assertNull($refused->retryAfter);
    }

    /**
     * The package's audience policy over a configuration whose `api` guard
     * requires a verified identifier; it needs no token service to admit.
     *
     * @return \SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy
     */
    private function packagePolicy(): GuardAudiencePolicy
    {
        $config = new Repository([
            'auth'           => ['guards' => ['api' => ['driver' => 'jwt', 'audience' => ['require_verified_identifier' => true]]]],
            'authentication' => ['audience' => ['methods' => ['password'], 'principal_types' => null, 'require_verified_identifier' => false]],
        ]);

        return new GuardAudiencePolicy($config, (new \ReflectionClass(JwtTokenServiceFactory::class))->newInstanceWithoutConstructor());
    }

    /**
     * Build the admission over the audience policy mock.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\SignInAdmission
     */
    private function admission(): SignInAdmission
    {
        return new SignInAdmission($this->audience);
    }

    /**
     * Build an activatable principal reporting the given state and acting
     * within the given tenant.
     *
     * @param  bool  $active
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principal(bool $active, ?Tenant $tenant): MockInterface
    {
        $principal = \Mockery::mock(Principal::class, CanBeActive::class);
        $principal->shouldReceive('isActive')->once()->andReturn($active);
        $principal->shouldReceive('getTenant')->once()->andReturn($tenant);

        return $principal;
    }

    /**
     * Build an activatable identity that reports inactive once.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function inactiveIdentity(): MockInterface
    {
        $identity = \Mockery::mock(Identity::class, CanBeActive::class);
        $identity->shouldReceive('isActive')->once()->andReturnFalse();

        return $identity;
    }

    /**
     * Build an activatable tenant that reports the given state once.
     *
     * @param  bool  $active
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Tenant
     */
    private function tenant(bool $active): MockInterface
    {
        $tenant = \Mockery::mock(Tenant::class, CanBeActive::class);
        $tenant->shouldReceive('isActive')->once()->andReturn($active);

        return $tenant;
    }
}
