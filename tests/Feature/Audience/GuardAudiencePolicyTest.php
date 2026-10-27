<?php

declare(strict_types = 1);

namespace Tests\Feature\Audience;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubTenant;
use Tests\Unit\Stubs\StubVerifiableIdentity;

/**
 * Feature tests for the package audience policy resolved from the container
 * over each guard's `audience` configuration and the package defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardAudiencePolicy::class)]
final class GuardAudiencePolicyTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Guard without an `audience` block. */
    private const string GUARD = 'api';

    /**
     * The container binds the contract to the package policy, once.
     *
     * @return void
     */
    public function testContainerBindsThePackagePolicyAsASingleton(): void
    {
        self::assertInstanceOf(GuardAudiencePolicy::class, $this->policy());
        self::assertSame($this->policy(), $this->policy());
    }

    /**
     * Out of the box a guard lets only the password method start sessions,
     * compared exactly, and admits any principal, typed or not.
     *
     * @return void
     */
    public function testShippedDefaultsAllowOnlyPasswordAndAdmitAnyPrincipal(): void
    {
        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'password'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'sso'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'Password'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, ''));
        self::assertNull($this->admit(new PlainPrincipalFixture(1)));
        self::assertNull($this->admit($this->principalOfType('customer')));
    }

    /**
     * A guard's `methods` replace the package list rather than adding to it.
     *
     * @return void
     */
    public function testGuardMethodsReplaceThePackageMethods(): void
    {
        $this->setGuardAudience(['methods' => ['sso', 'phone_code']]);

        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'sso'));
        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'phone_code'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'password'));
        self::assertTrue($this->policy()->allowsMethod('other', 'password'));
    }

    /**
     * A guard that lists principal types admits a principal whose own type, or
     * whose tenant's type, is listed, and refuses one of another type or of no
     * type as `principal_ineligible`.
     *
     * @return void
     */
    public function testListedPrincipalTypesAdmitOnlyThoseTypes(): void
    {
        $this->setGuardAudience(['principal_types' => ['staff', 'client_admin']]);

        $tenant = new StubTenant;
        $tenant->setRawAttributes(['type' => 'staff']);

        self::assertNull($this->admit($this->principalOfType('client_admin')));
        self::assertNull($this->admit(new PlainPrincipalFixture(1, tenant: $tenant)));
        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->admit($this->principalOfType('customer')));
        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->admit($this->principalOfType('Staff')));
        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->admit(new PlainPrincipalFixture(1)));
    }

    /**
     * A guard's key wins even when it is `null`: a guard can admit any
     * principal although the package default lists types.
     *
     * @return void
     */
    public function testGuardNullPrincipalTypesOverridesThePackageList(): void
    {
        config()->set('authentication.audience.principal_types', ['staff']);

        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->admit(new PlainPrincipalFixture(1), 'other'));

        $this->setGuardAudience(['principal_types' => null]);

        self::assertNull($this->admit(new PlainPrincipalFixture(1)));
    }

    /**
     * A guard whose `audience` entry is `null` keeps the package defaults.
     *
     * @return void
     */
    public function testNullGuardAudienceBlockMeansNoOverrides(): void
    {
        config()->set('authentication.audience.methods', ['sso']);

        $this->setGuardAudience(null);

        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'sso'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'password'));
    }

    /**
     * Without per-type lifetimes a principal gets the guard's lifetimes; with
     * them, a principal of a listed type gets its type's, exactly as the
     * guard's token service issues them.
     *
     * @return void
     */
    public function testLifetimesAreTheGuardsForThePrincipalsType(): void
    {
        $tokens = $this->app?->make(JwtTokenServiceFactory::class);

        self::assertInstanceOf(JwtTokenServiceFactory::class, $tokens);
        self::assertSame($tokens->forGuard(self::GUARD)->lifetimes(), $this->policy()->lifetimes(self::GUARD, $this->principalOfType('staff')));

        config()->set('auth.guards.other.jwt.by_principal_type', ['staff' => ['access_ttl_minutes' => 3, 'refresh_absolute_ttl_minutes' => 4000]]);

        $staff = $this->policy()->lifetimes('other', $this->principalOfType('staff'));

        self::assertSame(3, $staff->accessTtlMinutes);
        self::assertSame(4000, $staff->refreshAbsoluteTtlMinutes);
        self::assertSame($tokens->forGuard('other')->lifetimes(), $this->policy()->lifetimes('other', $this->principalOfType('customer')));
    }

    /**
     * The verified-identifier gate is off by default: an unverified identifier
     * signs in.
     *
     * @return void
     */
    public function testVerifiedIdentifierIsNotRequiredByDefault(): void
    {
        self::assertNull($this->policy()->admit(self::GUARD, $this->verifiable(false), new PlainPrincipalFixture(1), 'email'));
    }

    /**
     * With the gate on, a sign-in with an identifier of a type is admitted only
     * when the identity reports that identifier verified; a sign-in that used
     * no identifier is not gated.
     *
     * @return void
     */
    public function testGateRequiresTheSignInsIdentifierToBeVerified(): void
    {
        $this->setGuardAudience(['require_verified_identifier' => true]);

        self::assertNull($this->policy()->admit(self::GUARD, $this->verifiable(true), new PlainPrincipalFixture(1), 'email'));
        self::assertSame(SignInFailureReason::IDENTIFIER_UNVERIFIED, $this->policy()->admit(self::GUARD, $this->verifiable(false), new PlainPrincipalFixture(1), 'email'));
        self::assertSame(SignInFailureReason::IDENTIFIER_UNVERIFIED, $this->policy()->admit(self::GUARD, $this->verifiable(true), new PlainPrincipalFixture(1), 'phone'));
        self::assertNull($this->policy()->admit(self::GUARD, $this->verifiable(false), new PlainPrincipalFixture(1), null));
        self::assertNull($this->policy()->admit('other', $this->verifiable(false), new PlainPrincipalFixture(1), 'email'));
    }

    /**
     * An ineligible principal is refused as such before its identifier is
     * looked at.
     *
     * @return void
     */
    public function testEligibilityIsDecidedBeforeTheGate(): void
    {
        $this->setGuardAudience(['require_verified_identifier' => true, 'principal_types' => ['staff']]);

        self::assertSame(SignInFailureReason::PRINCIPAL_INELIGIBLE, $this->policy()->admit(self::GUARD, $this->verifiable(false), $this->principalOfType('customer'), 'email'));
    }

    /**
     * With the gate on, an identity that cannot report its verified identifiers
     * is a misconfiguration, never admitted.
     *
     * @return void
     */
    public function testGateOnAnIdentityWithoutTheCapabilityIsReported(): void
    {
        config()->set('authentication.audience.require_verified_identifier', true);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(PlainIdentityFixture::class . ' cannot verify identifiers');

        $this->policy()->admit(self::GUARD, $this->identity(), new PlainPrincipalFixture(1), 'email');
    }

    /**
     * Malformed audience configuration: where it is set, the value, and the
     * message naming the guard and the key.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        $methods = 'Audience `methods` for guard [api] must be a non-empty list of sign-in method names:'
            . ' set `authentication.audience.methods` or the guard\'s `audience.methods` override.';
        $types = 'Audience `principal_types` for guard [api] must be null or a non-empty list of principal types:'
            . ' set `authentication.audience.principal_types` or the guard\'s `audience.principal_types` override.';
        $gate = 'Audience `require_verified_identifier` for guard [api] must be true or false:'
            . ' set `authentication.audience.require_verified_identifier` or the guard\'s `audience.require_verified_identifier` override.';

        yield from [
            'methods empty'              => ['methods', [], $methods],
            'methods a string'           => ['methods', 'password', $methods],
            'methods null'               => ['methods', null, $methods],
            'methods keyed'              => ['methods', ['main' => 'password'], $methods],
            'methods with an empty name' => ['methods', ['password', ''], $methods],
            'methods with a non-string'  => ['methods', ['password', 1], $methods],
            'types empty'                => ['principal_types', [], $types],
            'types a string'             => ['principal_types', 'staff', $types],
            'types keyed'                => ['principal_types', [1 => 'staff'], $types],
            'types with an empty name'   => ['principal_types', [''], $types],
            'types with a null'          => ['principal_types', ['staff', null], $types],
            'types false'                => ['principal_types', false, $types],
            'gate a string'              => ['require_verified_identifier', 'yes', $gate],
            'gate an integer'            => ['require_verified_identifier', 1, $gate],
            'gate null'                  => ['require_verified_identifier', null, $gate],
        ];
    }

    /**
     * A malformed guard setting fails closed on whichever check uses the guard
     * first, never read as allowing or admitting.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedGuardSettingFailsClosedOnEveryCheck(string $key, mixed $value, string $message): void
    {
        $this->setGuardAudience([$key => $value]);

        $this->assertFailsClosed($message, fn (): bool => $this->policy()->allowsMethod(self::GUARD, 'password'));
        $this->assertFailsClosed($message, fn (): ?SignInFailureReason => $this->admit(new PlainPrincipalFixture(1)));
    }

    /**
     * A malformed package setting fails closed for a guard that does not
     * override it.
     *
     * @param  string  $key
     * @param  mixed  $value
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedSettings')]
    public function testMalformedPackageSettingFailsClosed(string $key, mixed $value, string $message): void
    {
        config()->set("authentication.audience.{$key}", $value);

        $this->assertFailsClosed($message, fn (): bool => $this->policy()->allowsMethod(self::GUARD, 'password'));
    }

    /**
     * A key missing at both levels fails closed: the policy carries no literal
     * default of its own.
     *
     * @return void
     */
    public function testSettingMissingAtBothLevelsFailsClosed(): void
    {
        config()->set('authentication.audience', ['methods' => ['password']]);

        $this->assertFailsClosed(
            'Audience `principal_types` for guard [api] must be set:'
            . ' set `authentication.audience.principal_types` or the guard\'s `audience.principal_types` override.',
            fn (): bool => $this->policy()->allowsMethod(self::GUARD, 'password'),
        );
    }

    /**
     * Audience blocks that are not arrays, or hold a key the policy does not
     * know, fail closed rather than being ignored.
     *
     * @return void
     */
    public function testMalformedBlocksFailClosed(): void
    {
        $check = fn (): bool => $this->policy()->allowsMethod(self::GUARD, 'password');

        $this->setGuardAudience('password');
        $this->assertFailsClosed('Audience configuration for guard [api]: the guard\'s `audience` overrides must be an array.', $check);

        $this->setGuardAudience(['method' => ['password']]);
        $this->assertFailsClosed('Audience configuration for guard [api]: the guard\'s `audience` overrides has an unknown key `method`.', $check);

        $this->setGuardAudience(['password']);
        $this->assertFailsClosed('Audience configuration for guard [api]: the guard\'s `audience` overrides has an unknown key `0`.', $check);

        $this->setGuardAudience(null);

        config()->set('authentication.audience', null);
        $this->assertFailsClosed('Audience configuration for guard [api]: `authentication.audience` must be an array.', $check);

        config()->set('authentication.audience', ['methods' => ['password'], 'principal_types' => null, 'limits' => []]);
        $this->assertFailsClosed('Audience configuration for guard [api]: `authentication.audience` has an unknown key `limits`.', $check);
    }

    /**
     * A guard that is not configured is reported rather than given the package
     * defaults.
     *
     * @return void
     */
    public function testUnconfiguredGuardFailsClosed(): void
    {
        $this->assertFailsClosed('Auth guard [missing] is not configured.', fn (): bool => $this->policy()->allowsMethod('missing', 'password'));
    }

    /**
     * Configure two guards without audience blocks.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'users']);
        $config->set('auth.guards.other', ['driver' => 'jwt', 'provider' => 'users']);
    }

    /**
     * The audience policy the container binds.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy
     */
    private function policy(): AudiencePolicy
    {
        $policy = $this->app?->make(AudiencePolicy::class);

        self::assertInstanceOf(AudiencePolicy::class, $policy);

        return $policy;
    }

    /**
     * Ask the policy to admit the principal to the guard, for an identity that
     * owns it and a sign-in that used no identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason
     */
    private function admit(Principal $principal, string $guard = self::GUARD): ?SignInFailureReason
    {
        return $this->policy()->admit($guard, $this->identity(), $principal, null);
    }

    /**
     * An identity the policy does not need to read.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(): Identity
    {
        return new PlainIdentityFixture(1);
    }

    /**
     * An identity whose email address is verified or not.
     *
     * @param  bool  $verified
     * @return \Tests\Unit\Stubs\StubVerifiableIdentity
     */
    private function verifiable(bool $verified): StubVerifiableIdentity
    {
        $identity = new StubVerifiableIdentity(1, ['email' => 'ben@example.com', 'phone' => '+447700900123']);

        if ($verified) {
            $identity->markIdentifierAsVerified('email', 'ben@example.com');
        }

        return $identity;
    }

    /**
     * Build a principal reporting the given type, acting within no tenant.
     *
     * @param  string  $type
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principalOfType(string $type): Principal
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasType&\SineMacula\Laravel\Authentication\Contracts\Principal $principal */
        $principal = \Mockery::mock(Principal::class, HasType::class);
        $principal->shouldReceive('getType')->andReturn($type);
        $principal->shouldReceive('getTenant')->andReturn(null);

        return $principal;
    }

    /**
     * Set the guard's `audience` block.
     *
     * @param  mixed  $audience
     * @return void
     */
    private function setGuardAudience(mixed $audience): void
    {
        config()->set('auth.guards.' . self::GUARD . '.audience', $audience);
    }

    /**
     * Assert the check throws an `InvalidArgumentException` with exactly the
     * given message.
     *
     * @param  string  $message
     * @param  \Closure(): mixed  $check
     * @return void
     */
    private function assertFailsClosed(string $message, \Closure $check): void
    {
        try {
            $check();
        } catch (\InvalidArgumentException $e) {
            self::assertSame($message, $e->getMessage());

            return;
        }

        self::fail('Expected the policy to fail closed with: ' . $message);
    }
}
