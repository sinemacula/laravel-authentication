<?php

declare(strict_types = 1);

namespace Tests\Feature\Applications;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\StubTenant;
use Tests\Unit\Stubs\StubVerifiableIdentity;

/**
 * Feature tests for the package application policy resolved from the container
 * over each guard's `application` configuration and the package defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardApplicationPolicy::class)]
final class GuardApplicationPolicyTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string Guard without an `application` block. */
    private const string GUARD = 'api';

    /**
     * The container binds the contract to the package policy, once.
     *
     * @return void
     */
    public function testContainerBindsThePackagePolicyAsASingleton(): void
    {
        self::assertInstanceOf(GuardApplicationPolicy::class, $this->policy());
        self::assertSame($this->policy(), $this->policy());
    }

    /**
     * The shipped defaults, read from the package's own configuration file,
     * list no method and require no verified identifier, so out of the box an
     * application allows nothing until it lists what it uses, and admits any
     * principal, in a tenant or not.
     *
     * @return void
     */
    public function testShippedDefaultsAllowNothingAndAdmitAnyPrincipal(): void
    {
        /** @var array<string, mixed> $shipped */
        $shipped = require dirname(__DIR__, 3) . '/config/authentication.php';

        self::assertSame(['methods' => [], 'require_verified_identifier' => false], $shipped['application']);

        config()->set('authentication.application', $shipped['application']);

        foreach (self::everyName() as $name) {
            self::assertFalse($this->policy()->allowsMethod(self::GUARD, $name), "The shipped defaults allow `{$name}`.");
        }

        self::assertNull($this->admit(new PlainPrincipalFixture(1)));
        self::assertNull($this->admit(new PlainPrincipalFixture(2, tenant: new StubTenant)));
    }

    /**
     * Only a name the methods list holds, compared exactly, is allowed.
     *
     * @return void
     */
    public function testOnlyAListedNameIsAllowed(): void
    {
        $this->setGuardApplication(['methods' => ['password']]);

        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'password'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'sso'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'Password'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, ''));
    }

    /**
     * An empty list at guard level is the guard's, over a package list that
     * names methods: the application allows nothing, and validates.
     *
     * @return void
     */
    public function testAnEmptyGuardListAllowsNothingOverThePackageList(): void
    {
        config()->set('authentication.application.methods', self::everyName());

        $this->setGuardApplication(['methods' => []]);

        $this->packagePolicy()->validate(self::GUARD);

        foreach (self::everyName() as $name) {
            self::assertFalse($this->policy()->allowsMethod(self::GUARD, $name), "An empty list allows `{$name}`.");
            self::assertTrue($this->policy()->allowsMethod('other', $name));
        }
    }

    /**
     * The package policy has no rule about principals: `admit()` answers
     * exactly as `admitIdentifier()` does, without reading the principal.
     *
     * @return void
     */
    public function testAdmitIsTheVerifiedIdentifierGateAlone(): void
    {
        $this->setGuardApplication(['require_verified_identifier' => true]);

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldNotReceive('getTenant');

        foreach ([[true, 'email'], [false, 'email'], [true, 'phone'], [false, null]] as [$verified, $type]) {
            self::assertSame(
                $this->policy()->admitIdentifier(self::GUARD, $this->verifiable($verified), $type),
                $this->policy()->admit(self::GUARD, $this->verifiable($verified), $principal, $type),
            );
        }

        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->policy()->admit(self::GUARD, $this->verifiable(false), $principal, 'email'));
    }

    /**
     * A guard's `methods` replace the package list rather than adding to it.
     *
     * @return void
     */
    public function testGuardMethodsReplaceThePackageMethods(): void
    {
        config()->set('authentication.application.methods', ['password']);

        $this->setGuardApplication(['methods' => ['sso', 'phone_code']]);

        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'sso'));
        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'phone_code'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'password'));
        self::assertTrue($this->policy()->allowsMethod('other', 'password'));
    }

    /**
     * `methods()` lists the names the guard's own list holds, in its order,
     * whether or not anything is registered under them, else the package
     * list's; an empty list lists nothing.
     *
     * @return void
     */
    public function testMethodsListsTheGuardsResolvedNames(): void
    {
        config()->set('authentication.application.methods', ['password']);

        $this->setGuardApplication(['methods' => ['sso', 'api_key', 'unregistered']]);

        self::assertSame(['sso', 'api_key', 'unregistered'], $this->packagePolicy()->methods(self::GUARD));
        self::assertSame(['password'], $this->packagePolicy()->methods('other'));

        $this->setGuardApplication(['methods' => []]);

        self::assertSame([], $this->packagePolicy()->methods(self::GUARD));
    }

    /**
     * Neither a guard's `audience` block nor `authentication.audience` is an
     * application setting: a guard that lists its methods only there has no
     * `application` block, so it allows nothing, and validates.
     *
     * @return void
     */
    public function testAnAudienceBlockIsNotRead(): void
    {
        config()->set('auth.guards.' . self::GUARD . '.audience', ['methods' => ['password']]);
        config()->set('authentication.audience', ['methods' => ['password'], 'require_verified_identifier' => false]);

        $this->packagePolicy()->validate(self::GUARD);

        self::assertSame([], $this->packagePolicy()->methods(self::GUARD));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'password'));
    }

    /**
     * A guard whose `application` entry is `null` keeps the package defaults.
     *
     * @return void
     */
    public function testNullGuardApplicationBlockMeansNoOverrides(): void
    {
        config()->set('authentication.application.methods', ['sso']);

        $this->setGuardApplication(null);

        self::assertTrue($this->policy()->allowsMethod(self::GUARD, 'sso'));
        self::assertFalse($this->policy()->allowsMethod(self::GUARD, 'password'));
    }

    /**
     * Each guard's lifetimes are exactly those its token service issues with,
     * so a guard that overrides them gets its own.
     *
     * @return void
     */
    public function testLifetimesAreTheGuardsTokenServices(): void
    {
        config()->set('auth.guards.other.jwt', ['access_ttl_minutes' => 3, 'refresh_absolute_ttl_minutes' => 4000]);

        $tokens = $this->app?->make(JwtTokenServiceFactory::class);

        self::assertInstanceOf(JwtTokenServiceFactory::class, $tokens);
        self::assertSame($tokens->forGuard(self::GUARD)->lifetimes(), $this->policy()->lifetimes(self::GUARD));
        self::assertSame($tokens->forGuard('other')->lifetimes(), $this->policy()->lifetimes('other'));
        self::assertSame(3, $this->policy()->lifetimes('other')->accessTtlMinutes);
        self::assertSame(4000, $this->policy()->lifetimes('other')->refreshAbsoluteTtlMinutes);
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
        $this->setGuardApplication(['require_verified_identifier' => true]);

        self::assertNull($this->policy()->admit(self::GUARD, $this->verifiable(true), new PlainPrincipalFixture(1), 'email'));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->policy()->admit(self::GUARD, $this->verifiable(false), new PlainPrincipalFixture(1), 'email'));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $this->policy()->admit(self::GUARD, $this->verifiable(true), new PlainPrincipalFixture(1), 'phone'));
        self::assertNull($this->policy()->admit(self::GUARD, $this->verifiable(false), new PlainPrincipalFixture(1), null));
        self::assertNull($this->policy()->admit('other', $this->verifiable(false), new PlainPrincipalFixture(1), 'email'));
    }

    /**
     * The gate alone, for the identity before any principal: with the gate on,
     * an identifier of a type is admitted only when the identity reports it
     * verified, while a sign-in that used no identifier, or a guard without the
     * gate, admits it without reading the identity.
     *
     * @return void
     */
    public function testTheGateAloneDecidesForTheIdentity(): void
    {
        $this->setGuardApplication(['require_verified_identifier' => true]);

        $policy = $this->packagePolicy();

        self::assertNull($policy->admitIdentifier(self::GUARD, $this->verifiable(true), 'email'));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $policy->admitIdentifier(self::GUARD, $this->verifiable(false), 'email'));
        self::assertSame(FailureReason::IDENTIFIER_UNVERIFIED, $policy->admitIdentifier(self::GUARD, $this->verifiable(true), 'phone'));
        self::assertNull($policy->admitIdentifier(self::GUARD, $this->identity(), null));
        self::assertNull($policy->admitIdentifier('other', $this->identity(), 'email'));
    }

    /**
     * With the gate on, an identity that cannot report its verified identifiers
     * is a misconfiguration, never admitted.
     *
     * @return void
     */
    public function testGateOnAnIdentityWithoutTheCapabilityIsReported(): void
    {
        config()->set('authentication.application.require_verified_identifier', true);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(PlainIdentityFixture::class . ' cannot verify identifiers');

        $this->policy()->admit(self::GUARD, $this->identity(), new PlainPrincipalFixture(1), 'email');
    }

    /**
     * Malformed application configuration: where it is set, the value, and the
     * message naming the guard and the key.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedSettings(): iterable
    {
        $methods = 'Application `methods` for guard [api] must be a list of lower-case sign-in method names:'
            . ' set `authentication.application.methods` or the guard\'s `application.methods` override.';
        $gate = 'Application `require_verified_identifier` for guard [api] must be true or false:'
            . ' set `authentication.application.require_verified_identifier` or the guard\'s `application.require_verified_identifier` override.';

        yield from [
            'methods a string'           => ['methods', 'password', $methods],
            'methods null'               => ['methods', null, $methods],
            'methods keyed'              => ['methods', ['main' => 'password'], $methods],
            'methods out of order'       => ['methods', [1 => 'password'], $methods],
            'methods with an empty name' => ['methods', ['password', ''], $methods],
            'methods with a non-string'  => ['methods', ['password', 1], $methods],
            'methods with a capital'     => ['methods', ['Password'], $methods],
            'methods with a hyphen'      => ['methods', ['password', 'pass-word'], $methods],
            'methods with a space'       => ['methods', ['password '], $methods],
            'methods with a digit first' => ['methods', ['2fa'], $methods],
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
        $this->setGuardApplication([$key => $value]);

        $this->assertFailsClosed($message, fn (): bool => $this->policy()->allowsMethod(self::GUARD, 'password'));
        $this->assertFailsClosed($message, fn (): ?FailureReason => $this->admit(new PlainPrincipalFixture(1)));
        $this->assertFailsClosed($message, function (): bool {
            $this->packagePolicy()->validate(self::GUARD);

            return true;
        });
        $this->assertFailsClosed($message, fn (): array => $this->packagePolicy()->methods(self::GUARD));
    }

    /**
     * Validating a guard whose settings are well formed reports nothing and
     * leaves its decisions as they were.
     *
     * @return void
     */
    public function testValidatingWellFormedSettingsPasses(): void
    {
        $this->setGuardApplication(['methods' => ['password', 'api_key']]);

        $policy = $this->packagePolicy();

        $policy->validate(self::GUARD);

        self::assertTrue($policy->allowsMethod(self::GUARD, 'password'));
        self::assertTrue($policy->allowsMethod(self::GUARD, 'api_key'));
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
        config()->set("authentication.application.{$key}", $value);

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
        config()->set('authentication.application', ['methods' => ['password']]);

        $this->assertFailsClosed(
            'Application `require_verified_identifier` for guard [api] must be set:'
            . ' set `authentication.application.require_verified_identifier` or the guard\'s `application.require_verified_identifier` override.',
            fn (): bool => $this->policy()->allowsMethod(self::GUARD, 'password'),
        );
    }

    /**
     * Application blocks that are not arrays, or hold a key the policy does not
     * know, fail closed rather than being ignored.
     *
     * @return void
     */
    public function testMalformedBlocksFailClosed(): void
    {
        $check = fn (): bool => $this->policy()->allowsMethod(self::GUARD, 'password');

        $this->setGuardApplication('password');
        $this->assertFailsClosed('Application configuration for guard [api]: the guard\'s `application` overrides must be an array.', $check);

        $this->setGuardApplication(['method' => ['password']]);
        $this->assertFailsClosed('Application configuration for guard [api]: the guard\'s `application` overrides has an unknown key `method`.', $check);

        $this->setGuardApplication(['password']);
        $this->assertFailsClosed('Application configuration for guard [api]: the guard\'s `application` overrides has an unknown key `0`.', $check);

        $this->setGuardApplication(['principal_types' => null]);
        $this->assertFailsClosed('Application configuration for guard [api]: the guard\'s `application` overrides has an unknown key `principal_types`.', $check);

        $this->setGuardApplication(null);

        config()->set('authentication.application', null);
        $this->assertFailsClosed('Application configuration for guard [api]: `authentication.application` must be an array.', $check);

        config()->set('authentication.application', ['methods' => ['password'], 'require_verified_identifier' => false, 'limits' => []]);
        $this->assertFailsClosed('Application configuration for guard [api]: `authentication.application` has an unknown key `limits`.', $check);

        config()->set('authentication.application', ['methods' => ['password'], 'require_verified_identifier' => false, 'principal_types' => ['staff']]);
        $this->assertFailsClosed('Application configuration for guard [api]: `authentication.application` has an unknown key `principal_types`.', $check);
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
     * Configure two guards without application blocks.
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
     * Every name an application can list: the package's sign-in methods and
     * both machine credentials.
     *
     * @return list<string>
     */
    private static function everyName(): array
    {
        return ['password', 'phone_code', 'email_code', 'passkey', ...SignInMethodManager::CREDENTIAL_METHODS];
    }

    /**
     * Resolve the bound policy, which is the package's.
     *
     * @return \SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy
     */
    private function packagePolicy(): GuardApplicationPolicy
    {
        $policy = $this->policy();

        self::assertInstanceOf(GuardApplicationPolicy::class, $policy);

        return $policy;
    }

    /**
     * The application policy the container binds.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy
     */
    private function policy(): ApplicationPolicy
    {
        $policy = $this->app?->make(ApplicationPolicy::class);

        self::assertInstanceOf(ApplicationPolicy::class, $policy);

        return $policy;
    }

    /**
     * Ask the policy to admit the principal to the guard, for an identity that
     * owns it and a sign-in that used no identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private function admit(Principal $principal, string $guard = self::GUARD): ?FailureReason
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
     * Set the guard's `application` block.
     *
     * @param  mixed  $application
     * @return void
     */
    private function setGuardApplication(mixed $application): void
    {
        config()->set('auth.guards.' . self::GUARD . '.application', $application);
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
