<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
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
     * An identity that owns devices may be signed in; one that does not is
     * refused as a misconfiguration naming its class.
     *
     * @return void
     */
    public function testOnlyAnIdentityThatOwnsDevicesMayStartASession(): void
    {
        SessionPreconditions::assertHoldsDevices(\Mockery::mock(Identity::class, HasDevices::class));

        $identity = \Mockery::mock(Identity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(
            'The session service can only start sessions for identities that implement %s; %s does not. '
            . 'Sign this guard\'s identities in with attempt() and issue access tokens instead.',
            HasDevices::class,
            $identity::class,
        ));

        SessionPreconditions::assertHoldsDevices($identity);
    }

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
     * A sign-in method may refuse only with a reason a method may give; any
     * other is reported as the misconfiguration it is, naming the method.
     *
     * @return void
     */
    public function testAMethodMayRefuseOnlyWithAMethodsReason(): void
    {
        $method = \Mockery::mock(SignInMethod::class);

        self::assertSame(FailureReason::INVALID_CREDENTIALS, SessionPreconditions::methodReason($method, FailureReason::INVALID_CREDENTIALS));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(sprintf(
            'Sign-in method %s refused a sign-in as `identity_inactive`, which only the session service may decide;'
            . ' a method answers `invalid_credentials` or another sign-in method reason.',
            $method::class,
        ));

        SessionPreconditions::methodReason($method, FailureReason::IDENTITY_INACTIVE);
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
