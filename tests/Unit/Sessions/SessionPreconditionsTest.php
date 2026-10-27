<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SessionPreconditions;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

/**
 * Unit tests for the checks the session service makes of what a caller hands
 * it: the principal a session for an externally verified identity is pinned to,
 * and whether a reloaded identity is the one that was verified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionPreconditions::class)]
final class SessionPreconditionsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The pin is the principal given as the argument, or else the one on the
     * context, or none.
     *
     * @return void
     */
    public function testThePinIsTheArgumentOrElseTheContexts(): void
    {
        $argument  = \Mockery::mock(Principal::class);
        $onContext = \Mockery::mock(Principal::class);
        $client    = new ClientContext(null, null);

        self::assertSame($argument, SessionPreconditions::pinnedPrincipal($argument, new SignInContext($client)));
        self::assertSame($onContext, SessionPreconditions::pinnedPrincipal(null, new SignInContext($client, principal: $onContext)));
        self::assertNull(SessionPreconditions::pinnedPrincipal(null, new SignInContext($client)));
    }

    /**
     * A principal named both as the argument and on the context is refused,
     * even when it is the same one.
     *
     * @return void
     */
    public function testAPrincipalNamedTwiceIsRefused(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Name the principal to start a session as either as the argument or on the context, not both.');

        SessionPreconditions::pinnedPrincipal($principal, new SignInContext(new ClientContext(null, null), principal: $principal));
    }

    /**
     * A reloaded identity is the verified one only when it is of the same class
     * and has the same auth identifier, compared as identifiers are.
     *
     * @return void
     */
    public function testTheSameIdentityHasTheSameClassAndIdentifier(): void
    {
        self::assertTrue(SessionPreconditions::isSameIdentity($this->identity(7), $this->identity(7)));
        self::assertTrue(SessionPreconditions::isSameIdentity($this->identity(7), $this->identity('7')));
        self::assertFalse(SessionPreconditions::isSameIdentity($this->identity(7), $this->identity(8)));
        $otherClass = \Mockery::mock(Identity::class, Principal::class);
        $otherClass->shouldReceive('getAuthIdentifier')->andReturn(7);

        self::assertFalse(SessionPreconditions::isSameIdentity($otherClass, $this->identity(7)));
    }

    /**
     * `SessionPreconditions` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SessionPreconditions::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SessionPreconditions::class, $instance);
    }

    /**
     * Build an identity mock with the auth identifier.
     *
     * @param  int|string  $identifier
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(int|string $identifier): MockInterface
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn($identifier);

        return $identity;
    }
}
