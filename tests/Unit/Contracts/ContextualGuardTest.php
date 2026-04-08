<?php

declare(strict_types = 1);

namespace Tests\Unit\Contracts;

use Illuminate\Contracts\Auth\Authenticatable as LaravelAuthenticatable;
use Illuminate\Contracts\Auth\Guard as LaravelGuard;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Reflection-based structural tests for the ContextualGuard contract.
 *
 * Verifies that the published interface exposes the documented
 * contextual surface (accessors, setters, contextual `attempt`/`login`)
 * and that it inherits from Laravel's `Guard` contract. No instance of
 * the interface is constructed — the assertions run against interface
 * metadata only.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[CoversClass(ContextualGuard::class)]
final class ContextualGuardTest extends TestCase
{
    /**
     * The contract is an interface and extends Laravel's Guard contract.
     *
     * @return void
     */
    public function testContextualGuardExtendsLaravelGuardContract(): void
    {
        $reflection = new \ReflectionClass(ContextualGuard::class);

        self::assertTrue($reflection->isInterface(), 'ContextualGuard must be declared as an interface.');
        self::assertContains(
            LaravelGuard::class,
            $reflection->getInterfaceNames(),
            'ContextualGuard must extend Illuminate\Contracts\Auth\Guard.',
        );
    }

    /**
     * The contract declares every contextual accessor with the
     * documented nullable return type.
     *
     * @return void
     */
    public function testContextualGuardDeclaresContextualAccessors(): void
    {
        $expected = [
            'identity'     => Identity::class,
            'principal'    => Principal::class,
            'device'       => Device::class,
            'organization' => Organization::class,
            'scope'        => 'string',
        ];

        foreach ($expected as $method => $returnType) {

            $reflection = new \ReflectionMethod(ContextualGuard::class, $method);

            self::assertTrue($reflection->isPublic(), "{$method}() must be public.");

            $type = $reflection->getReturnType();

            self::assertInstanceOf(\ReflectionNamedType::class, $type, "{$method}() must declare a named return type.");
            self::assertTrue($type->allowsNull(), "{$method}() must return a nullable type.");
            self::assertSame($returnType, $type->getName(), "{$method}() must return ?{$returnType}.");
        }

        foreach (['isInternal', 'isExternal'] as $method) {

            $reflection = new \ReflectionMethod(ContextualGuard::class, $method);

            self::assertTrue($reflection->isPublic(), "{$method}() must be public.");

            $type = $reflection->getReturnType();

            self::assertInstanceOf(\ReflectionNamedType::class, $type, "{$method}() must declare a named return type.");
            self::assertFalse($type->allowsNull(), "{$method}() must return a non-nullable bool.");
            self::assertSame('bool', $type->getName(), "{$method}() must return bool.");
        }
    }

    /**
     * The contract declares `setPrincipal` and `setDevice` with a
     * `static` return type.
     *
     * @return void
     */
    public function testContextualGuardDeclaresContextualSetters(): void
    {
        $setters = [
            'setPrincipal' => Principal::class,
            'setDevice'    => Device::class,
        ];

        foreach ($setters as $method => $parameterType) {

            $reflection = new \ReflectionMethod(ContextualGuard::class, $method);

            self::assertTrue($reflection->isPublic(), "{$method}() must be public.");
            self::assertCount(1, $reflection->getParameters(), "{$method}() must accept exactly one parameter.");

            $parameter = $reflection->getParameters()[0];
            $paramType = $parameter->getType();

            self::assertInstanceOf(\ReflectionNamedType::class, $paramType, "{$method}() parameter must declare a named type.");
            self::assertFalse($paramType->allowsNull(), "{$method}() parameter must be non-nullable.");
            self::assertSame($parameterType, $paramType->getName(), "{$method}() must accept a {$parameterType}.");

            $returnType = $reflection->getReturnType();

            self::assertInstanceOf(\ReflectionNamedType::class, $returnType, "{$method}() must declare a named return type.");
            self::assertSame('static', $returnType->getName(), "{$method}() must return static.");
        }
    }

    /**
     * The contract declares contextual `attempt` and `login` methods
     * with the documented parameter and return types.
     *
     * @return void
     */
    public function testContextualGuardDeclaresContextualAttemptAndLogin(): void
    {
        $attempt = new \ReflectionMethod(ContextualGuard::class, 'attempt');

        self::assertTrue($attempt->isPublic(), 'attempt() must be public.');
        self::assertCount(3, $attempt->getParameters(), 'attempt() must accept three parameters.');

        $attemptParameters = $attempt->getParameters();

        self::assertSame('credentials', $attemptParameters[0]->getName());
        $credentialsType = $attemptParameters[0]->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $credentialsType);
        self::assertSame('array', $credentialsType->getName());

        self::assertSame('principal', $attemptParameters[1]->getName());
        $principalType = $attemptParameters[1]->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $principalType);
        self::assertTrue($principalType->allowsNull());
        self::assertSame(Principal::class, $principalType->getName());
        self::assertTrue($attemptParameters[1]->isDefaultValueAvailable());
        self::assertNull($attemptParameters[1]->getDefaultValue());

        self::assertSame('device', $attemptParameters[2]->getName());
        $deviceType = $attemptParameters[2]->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $deviceType);
        self::assertTrue($deviceType->allowsNull());
        self::assertSame(Device::class, $deviceType->getName());
        self::assertTrue($attemptParameters[2]->isDefaultValueAvailable());
        self::assertNull($attemptParameters[2]->getDefaultValue());

        $attemptReturn = $attempt->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $attemptReturn);
        self::assertFalse($attemptReturn->allowsNull());
        self::assertSame('bool', $attemptReturn->getName());

        $login = new \ReflectionMethod(ContextualGuard::class, 'login');

        self::assertTrue($login->isPublic(), 'login() must be public.');
        self::assertCount(3, $login->getParameters(), 'login() must accept three parameters.');

        $loginParameters = $login->getParameters();

        self::assertSame('identity', $loginParameters[0]->getName());
        $identityType = $loginParameters[0]->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $identityType);
        self::assertFalse($identityType->allowsNull());
        self::assertSame(Identity::class, $identityType->getName());

        self::assertSame('principal', $loginParameters[1]->getName());
        $loginPrincipalType = $loginParameters[1]->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $loginPrincipalType);
        self::assertFalse($loginPrincipalType->allowsNull());
        self::assertSame(Principal::class, $loginPrincipalType->getName());

        self::assertSame('device', $loginParameters[2]->getName());
        $loginDeviceType = $loginParameters[2]->getType();
        self::assertInstanceOf(\ReflectionNamedType::class, $loginDeviceType);
        self::assertTrue($loginDeviceType->allowsNull());
        self::assertSame(Device::class, $loginDeviceType->getName());
        self::assertTrue($loginParameters[2]->isDefaultValueAvailable());
        self::assertNull($loginParameters[2]->getDefaultValue());

        $loginReturn = $login->getReturnType();
        self::assertInstanceOf(\ReflectionNamedType::class, $loginReturn);
        self::assertFalse($loginReturn->allowsNull());
        self::assertSame('void', $loginReturn->getName());
    }

    /**
     * The Identity contract inherits from Laravel's Authenticatable
     * contract (structural verification of T10's output).
     *
     * @return void
     */
    public function testIdentityExtendsLaravelAuthenticatable(): void
    {
        $reflection = new \ReflectionClass(Identity::class);

        self::assertTrue($reflection->isInterface(), 'Identity must be declared as an interface.');
        self::assertContains(
            LaravelAuthenticatable::class,
            $reflection->getInterfaceNames(),
            'Identity must extend Illuminate\Contracts\Auth\Authenticatable.',
        );
    }
}
