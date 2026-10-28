<?php

declare(strict_types = 1);

namespace Tests\Unit\Contracts;

use Illuminate\Contracts\Auth\Authenticatable as LaravelAuthenticatable;
use Illuminate\Contracts\Auth\Guard as LaravelGuard;
use Illuminate\Contracts\Auth\UserProvider as LaravelUserProvider;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Contracts\CanBeActive;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasType;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\IdentifierNormaliser;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;

/**
 * Reflection-based structural tests for the package contracts.
 *
 * Pins the documented method surface of every contract and the inheritance
 * chains that let framework typehints resolve against package implementations.
 * Marked `#[CoversNothing]` because PHPUnit cannot attribute coverage to a bare
 * interface; the assertions run against interface metadata only.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[CoversNothing]
final class ContractDeclarationTest extends TestCase
{
    /**
     * `IdentityProvider` extends Laravel's framework `UserProvider` contract so
     * the package provider drops into Laravel's `Auth::createUserProvider()`
     * factory unchanged.
     *
     * @return void
     */
    public function testIdentityProviderExtendsLaravelUserProvider(): void
    {
        $reflection = new \ReflectionClass(IdentityProvider::class);

        self::assertTrue($reflection->isInterface());
        self::assertContains(LaravelUserProvider::class, $reflection->getInterfaceNames());
    }

    /**
     * `Identity` extends `Illuminate\Contracts\Auth\Authenticatable` so every
     * identity satisfies Laravel's framework typehints.
     *
     * @return void
     */
    public function testIdentityExtendsLaravelAuthenticatable(): void
    {
        $reflection = new \ReflectionClass(Identity::class);

        self::assertTrue($reflection->isInterface());
        self::assertContains(LaravelAuthenticatable::class, $reflection->getInterfaceNames());
    }

    /**
     * `Device` declares exactly the read surface the guards, the refresh
     * exchange, the session service, and the package events depend on: the
     * identifier, last use, both refresh digests and the rotation time, both
     * deadlines, the revocation, and the guard and sign-in method that started
     * the session.
     *
     * @return void
     */
    public function testDeviceContractDeclaresExactlyItsReadSurface(): void
    {
        self::assertSame([
            'getAbsoluteExpiresAt',
            'getDeviceIdentifier',
            'getGuard',
            'getIdleExpiresAt',
            'getLastUsedAt',
            'getPreviousRefreshKey',
            'getPrincipalSwitchedAt',
            'getRefreshKey',
            'getRefreshRotatedAt',
            'getRevokedAt',
            'getRevokedReason',
            'getSignInMethod',
            'getSignedInAt',
        ], self::declaredMethods(Device::class));
    }

    /**
     * `EloquentDevice` extends the generic `Device` contract with the relation
     * and column-name accessors required by refresh persistence paths.
     *
     * @return void
     */
    public function testEloquentDeviceExtendsDevice(): void
    {
        self::assertContains(
            Device::class,
            (new \ReflectionClass(EloquentDevice::class))->getInterfaceNames(),
        );
    }

    /**
     * `EloquentDevice` adds exactly the owner and principal relations and the
     * column names the session creation, refresh, revocation, and last-use
     * writes need. The identifier has no column name: it is always the primary
     * key.
     *
     * @return void
     */
    public function testEloquentDeviceContractDeclaresExactlyItsPersistenceHooks(): void
    {
        self::assertSame([
            'authenticatable',
            'getAbsoluteExpiresAtName',
            'getClientNameName',
            'getCreatedIpName',
            'getCreatedUserAgentName',
            'getGuardName',
            'getIdleExpiresAtName',
            'getLastUsedAtName',
            'getLastUsedIpName',
            'getLastUsedUserAgentName',
            'getPlatformName',
            'getPreviousRefreshKeyName',
            'getPrincipalSwitchedAtName',
            'getRefreshKeyName',
            'getRefreshRotatedAtName',
            'getRevokedAtName',
            'getRevokedReasonName',
            'getSignInMethodName',
            'getSignedInAtName',
            'principal',
        ], self::declaredMethods(EloquentDevice::class));
    }

    /**
     * `EloquentDevice::authenticatable()` and `principal()` must return MorphTo
     * relations, and the persistence column-name accessors must return strings.
     *
     * @return void
     */
    public function testEloquentDeviceDeclaresExpectedReturnTypes(): void
    {
        foreach (['authenticatable', 'principal'] as $relation) {
            $relationReturn = (new \ReflectionMethod(EloquentDevice::class, $relation))->getReturnType();
            self::assertInstanceOf(\ReflectionNamedType::class, $relationReturn);
            self::assertSame(MorphTo::class, $relationReturn->getName());
        }

        $columnNameAccessors = array_diff(self::declaredMethods(EloquentDevice::class), ['authenticatable', 'principal']);

        foreach ($columnNameAccessors as $method) {
            $returnType = (new \ReflectionMethod(EloquentDevice::class, $method))->getReturnType();
            self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
            self::assertSame('string', $returnType->getName());
        }
    }

    /**
     * Data provider listing the methods `Principal` must declare.
     *
     * @return \Generator<string, array{0: string}>
     */
    public static function providePrincipalContractMethods(): iterable
    {
        yield from [
            'getPrincipalIdentifier' => ['getPrincipalIdentifier'],
            'getIdentity'            => ['getIdentity'],
            'getTenant'              => ['getTenant'],
        ];
    }

    /**
     * `Principal` declares every method the contextual guards and default
     * resolver depend on.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('providePrincipalContractMethods')]
    public function testPrincipalContractDeclaresMethod(string $method): void
    {
        self::assertTrue(
            (new \ReflectionClass(Principal::class))->hasMethod($method),
            "Principal contract must declare {$method}().",
        );
    }

    /**
     * Activation is opt-in: `Principal` does not declare `isActive()`, the
     * `CanBeActive` capability does.
     *
     * @return void
     */
    public function testActivationIsDeclaredOnlyByTheCanBeActiveCapability(): void
    {
        self::assertFalse((new \ReflectionClass(Principal::class))->hasMethod('isActive'));
        self::assertTrue((new \ReflectionClass(CanBeActive::class))->hasMethod('isActive'));
    }

    /**
     * `Tenant` declares the identifier accessor used by the contextual
     * accessors.
     *
     * @return void
     */
    public function testTenantContractDeclaresGetTenantIdentifier(): void
    {
        self::assertTrue(
            (new \ReflectionClass(Tenant::class))->hasMethod('getTenantIdentifier'),
            'Tenant contract must declare getTenantIdentifier().',
        );
    }

    /**
     * `AudiencePolicy` declares exactly the three questions the session layer
     * asks a guard's audience: may this method start a session, may this
     * principal hold one, and for how long.
     *
     * @return void
     */
    public function testAudiencePolicyDeclaresExactlyItsChecks(): void
    {
        self::assertSame(['admit', 'allowsMethod', 'lifetimes'], self::declaredMethods(AudiencePolicy::class));
    }

    /**
     * `AttemptLimiter` declares the reserve-and-release pair for flows that
     * guess a secret and the read-and-count pair for flows that count only
     * failures.
     *
     * @return void
     */
    public function testAttemptLimiterDeclaresExactlyItsTwoCountingModes(): void
    {
        self::assertSame(['acquire', 'blocked', 'recordFailure', 'release'], self::declaredMethods(AttemptLimiter::class));
    }

    /**
     * Verifiable identifiers are a capability an identity opts into:
     * `HasVerifiableIdentifiers` declares reading the identifier, reading its
     * verification, and recording it, and `Identity` declares none of them.
     *
     * @return void
     */
    public function testVerifiableIdentifiersAreACapabilityOfTheIdentity(): void
    {
        self::assertSame(
            ['getIdentifierForVerification', 'hasVerifiedIdentifier', 'markIdentifierAsVerified'],
            self::declaredMethods(HasVerifiableIdentifiers::class),
        );
        self::assertFalse((new \ReflectionClass(Identity::class))->hasMethod('hasVerifiedIdentifier'));
    }

    /**
     * `IdentifierNormaliser` declares only `normalise()`, which may refuse a
     * value by returning `null`.
     *
     * @return void
     */
    public function testIdentifierNormaliserDeclaresOnlyNormalise(): void
    {
        $method = new \ReflectionMethod(IdentifierNormaliser::class, 'normalise');

        self::assertSame(['normalise'], self::declaredMethods(IdentifierNormaliser::class));
        self::assertSame('?string', (string) $method->getReturnType());
    }

    /**
     * A type is a capability a principal or a tenant opts into: `HasType`
     * declares only `getType()`, and neither `Principal` nor `Tenant` declares
     * it.
     *
     * @return void
     */
    public function testTypeIsDeclaredOnlyByTheHasTypeCapability(): void
    {
        self::assertSame(['getType'], self::declaredMethods(HasType::class));
        self::assertFalse((new \ReflectionClass(Principal::class))->hasMethod('getType'));
        self::assertFalse((new \ReflectionClass(Tenant::class))->hasMethod('getType'));
    }

    /**
     * `HasDevices::devices()` must return an
     * `Illuminate\Contracts\Database\Eloquent\Builder` so the guards'
     * `resolveDeviceFromHint()` path can query through a uniform surface.
     *
     * @return void
     */
    public function testHasDevicesDeclaresDevicesReturnType(): void
    {
        $reflection = new \ReflectionMethod(HasDevices::class, 'devices');

        $returnType = $reflection->getReturnType();

        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertSame(
            Builder::class,
            $returnType->getName(),
        );
    }

    /**
     * `HasPrincipals::principals()` must return an
     * `Illuminate\Contracts\Database\Eloquent\Builder` and
     * `resolveDefaultPrincipal()` must return a nullable `Principal`.
     *
     * @return void
     */
    public function testHasPrincipalsDeclaresReturnTypes(): void
    {
        $principalsReturn = (new \ReflectionMethod(HasPrincipals::class, 'principals'))->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $principalsReturn);
        self::assertSame(
            Builder::class,
            $principalsReturn->getName(),
        );

        $resolveReturn = (new \ReflectionMethod(HasPrincipals::class, 'resolveDefaultPrincipal'))->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $resolveReturn);
        self::assertTrue($resolveReturn->allowsNull());
        self::assertSame(Principal::class, $resolveReturn->getName());
    }

    /**
     * `ResolvesHintedPrincipal::resolveHintedPrincipal()` must return a
     * nullable `Principal`.
     *
     * @return void
     */
    public function testResolvesHintedPrincipalDeclaresReturnType(): void
    {
        $returnType = (new \ReflectionMethod(ResolvesHintedPrincipal::class, 'resolveHintedPrincipal'))->getReturnType();

        self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
        self::assertTrue($returnType->allowsNull());
        self::assertSame(Principal::class, $returnType->getName());
    }

    /**
     * `JwtGuard` implements the package `ContextualGuard` interface so
     * typehints on the package facade and service locator resolve correctly.
     *
     * @return void
     */
    public function testJwtGuardImplementsContextualGuard(): void
    {
        self::assertTrue(
            (new \ReflectionClass(JwtGuard::class))->implementsInterface(ContextualGuard::class),
            'JwtGuard must implement ContextualGuard.',
        );
    }

    /**
     * `JwtGuard` implements Laravel's framework `Guard` contract so first-party
     * `Auth::guard()->user()` calls return a framework- compatible guard.
     *
     * @return void
     */
    public function testJwtGuardImplementsLaravelGuard(): void
    {
        self::assertTrue(
            (new \ReflectionClass(JwtGuard::class))->implementsInterface(LaravelGuard::class),
            'JwtGuard must implement Illuminate\Contracts\Auth\Guard.',
        );
    }

    /**
     * Data provider listing every method on Laravel's `Guard` contract.
     *
     * @return \Generator<string, array{0: string}>
     */
    public static function provideLaravelGuardMethods(): iterable
    {
        yield from [
            'check'    => ['check'],
            'guest'    => ['guest'],
            'user'     => ['user'],
            'id'       => ['id'],
            'validate' => ['validate'],
            'hasUser'  => ['hasUser'],
            'setUser'  => ['setUser'],
        ];
    }

    /**
     * The shipped guard declares every method on Laravel's `Guard` contract.
     * Pins the full conformance surface in one reflection scan so a renamed
     * contract method fails the suite cleanly.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideLaravelGuardMethods')]
    public function testShippedGuardDeclaresLaravelGuardMethod(string $method): void
    {
        self::assertTrue(
            (new \ReflectionClass(JwtGuard::class))->hasMethod($method),
            "JwtGuard must declare {$method}().",
        );
    }

    /**
     * `SignInMethod` declares exactly what the session service asks of a
     * method: the identifier type, the identifier the input names, and the
     * verification itself.
     *
     * @return void
     */
    public function testSignInMethodDeclaresExactlyItsVerificationSurface(): void
    {
        self::assertSame(['authenticate', 'identifier', 'identifierType'], self::declaredMethods(SignInMethod::class));
    }

    /**
     * `AdditionalFactorPolicy` declares the one decision it makes.
     *
     * @return void
     */
    public function testAdditionalFactorPolicyDeclaresOneDecision(): void
    {
        self::assertSame(['requiresAdditionalFactor'], self::declaredMethods(AdditionalFactorPolicy::class));
    }

    /**
     * `AuthenticationEvent` declares only the context every package event
     * carries.
     *
     * @return void
     */
    public function testAuthenticationEventDeclaresOnlyItsContext(): void
    {
        self::assertSame(['context'], self::declaredMethods(AuthenticationEvent::class));
    }

    /**
     * Every event the package ships implements `AuthenticationEvent`, so one
     * listener on the contract receives them all.
     *
     * @return void
     */
    public function testEveryPackageEventImplementsAuthenticationEvent(): void
    {
        $events = [];

        foreach (glob(__DIR__ . '/../../../src/Events/*.php') ?: [] as $file) {

            $class = 'SineMacula\Laravel\Authentication\Events\\' . basename($file, '.php');

            if ($class === EventContext::class) {
                continue;
            }

            $events[$class] = (new \ReflectionClass($class))->implementsInterface(AuthenticationEvent::class);
        }

        self::assertNotEmpty($events);
        self::assertSame(array_fill_keys(array_keys($events), true), $events);
    }

    /**
     * "Tokens valid after" is a capability an identity or principal declares on
     * its own: reading the time and moving it forward.
     *
     * @return void
     */
    public function testTokensValidAfterIsACapabilityOfItsOwn(): void
    {
        self::assertSame(['getTokensValidAfter', 'invalidateTokensIssuedBefore'], self::declaredMethods(HasTokensValidAfter::class));
        self::assertNotContains(HasTokensValidAfter::class, (new \ReflectionClass(Identity::class))->getInterfaceNames());
        self::assertNotContains(HasTokensValidAfter::class, (new \ReflectionClass(Principal::class))->getInterfaceNames());
    }

    /**
     * The sorted names of the methods an interface declares itself, without the
     * ones it inherits.
     *
     * @param  class-string  $interface
     * @return list<string>
     */
    private static function declaredMethods(string $interface): array
    {
        $reflection = new \ReflectionClass($interface);

        $names = array_map(
            static fn (\ReflectionMethod $method): string => $method->getName(),
            array_filter(
                $reflection->getMethods(),
                static fn (\ReflectionMethod $method): bool => $method->getDeclaringClass()->getName() === $interface,
            ),
        );

        sort($names);

        return $names;
    }
}
