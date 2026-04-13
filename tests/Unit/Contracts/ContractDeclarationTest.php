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
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Guards\BasicGuard;
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
     * `IdentityProvider` extends Laravel's framework `UserProvider` contract
     * so the package provider drops into Laravel's `Auth::createUserProvider()`
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
     * Data provider listing the methods `Device` must declare.
     *
     * @return array<string, array{0: string}>
     */
    public static function provideDeviceContractMethods(): iterable
    {
        yield from [
            'getDeviceIdentifier'    => ['getDeviceIdentifier'],
            'getLastLoggedIn'        => ['getLastLoggedIn'],
            'getLastMfaVerification' => ['getLastMfaVerification'],
            'getOperatingSystem'     => ['getOperatingSystem'],
            'getRefreshKey'          => ['getRefreshKey'],
            'getRevokedAt'           => ['getRevokedAt'],
        ];
    }

    /**
     * `Device` declares every method the refresh-token exchange and
     * `ActsAsDevice` trait depend on. A reflection check kills a mutation that
     * removes or renames a contract method silently.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideDeviceContractMethods')]
    public function testDeviceContractDeclaresMethod(string $method): void
    {
        self::assertTrue(
            (new \ReflectionClass(Device::class))->hasMethod($method),
            "Device contract must declare {$method}().",
        );
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
     * Data provider listing the methods `EloquentDevice` must declare.
     *
     * @return array<string, array{0: string}>
     */
    public static function provideEloquentDeviceContractMethods(): iterable
    {
        yield from [
            'authenticatable'     => ['authenticatable'],
            'getLastLoggedInName' => ['getLastLoggedInName'],
            'getRefreshKeyName'   => ['getRefreshKeyName'],
            'getRevokedAtName'    => ['getRevokedAtName'],
        ];
    }

    /**
     * `EloquentDevice` declares every explicit Eloquent persistence hook the
     * refresh and last-seen paths depend on.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideEloquentDeviceContractMethods')]
    public function testEloquentDeviceContractDeclaresMethod(string $method): void
    {
        self::assertTrue(
            (new \ReflectionClass(EloquentDevice::class))->hasMethod($method),
            "EloquentDevice contract must declare {$method}().",
        );
    }

    /**
     * `EloquentDevice::authenticatable()` must return a MorphTo relation, and
     * the persistence column-name accessors must return strings.
     *
     * @return void
     *
     * @throws \ReflectionException
     */
    public function testEloquentDeviceDeclaresExpectedReturnTypes(): void
    {
        $authenticatableReturn = (new \ReflectionMethod(EloquentDevice::class, 'authenticatable'))->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $authenticatableReturn);
        self::assertSame(MorphTo::class, $authenticatableReturn->getName());

        foreach (['getLastLoggedInName', 'getRefreshKeyName', 'getRevokedAtName'] as $method) {
            $returnType = (new \ReflectionMethod(EloquentDevice::class, $method))->getReturnType();
            self::assertInstanceOf(\ReflectionNamedType::class, $returnType);
            self::assertSame('string', $returnType->getName());
        }
    }

    /**
     * Data provider listing the methods `Principal` must declare.
     *
     * @return array<string, array{0: string}>
     */
    public static function providePrincipalContractMethods(): iterable
    {
        yield from [
            'getPrincipalIdentifier' => ['getPrincipalIdentifier'],
            'getIdentity'            => ['getIdentity'],
            'getTenant'              => ['getTenant'],
            'isActive'               => ['isActive'],
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
     * `Tenant` declares the identifier accessor used by the contextual
     * accessors. Tenant scoping is otherwise opt-in via the `HasType`
     * capability interface.
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
     * `HasDevices::devices()` must return an
     * `Illuminate\Contracts\Database\Eloquent\Builder` so the JWT guard's
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
     * `JwtGuard` implements Laravel's framework `Guard` contract so
     * first-party `Auth::guard()->user()` calls return a framework- compatible
     * guard.
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
     * `BasicGuard` implements the package `ContextualGuard`.
     *
     * @return void
     */
    public function testBasicGuardImplementsContextualGuard(): void
    {
        self::assertTrue(
            (new \ReflectionClass(BasicGuard::class))->implementsInterface(ContextualGuard::class),
            'BasicGuard must implement ContextualGuard.',
        );
    }

    /**
     * `BasicGuard` implements Laravel's framework `Guard` contract.
     *
     * @return void
     */
    public function testBasicGuardImplementsLaravelGuard(): void
    {
        self::assertTrue(
            (new \ReflectionClass(BasicGuard::class))->implementsInterface(LaravelGuard::class),
            'BasicGuard must implement Illuminate\Contracts\Auth\Guard.',
        );
    }

    /**
     * Data provider listing every method on Laravel's `Guard` contract.
     *
     * @return array<string, array{0: string}>
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
     * Both shipped guards declare every method on Laravel's `Guard` contract.
     * Pins the full conformance surface in one reflection scan per guard class
     * so a renamed contract method fails the suite cleanly.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideLaravelGuardMethods')]
    public function testShippedGuardsDeclareLaravelGuardMethod(string $method): void
    {
        self::assertTrue(
            (new \ReflectionClass(JwtGuard::class))->hasMethod($method),
            "JwtGuard must declare {$method}().",
        );
        self::assertTrue(
            (new \ReflectionClass(BasicGuard::class))->hasMethod($method),
            "BasicGuard must declare {$method}().",
        );
    }
}
