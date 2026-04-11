<?php

declare(strict_types = 1);

namespace Tests\Unit\Resolvers;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Unit tests for the DefaultPrincipalResolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(DefaultPrincipalResolver::class)]
final class DefaultPrincipalResolverTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Asserts the 2D path returns the identity itself when it also implements
     * the Principal contract.
     *
     * @return void
     */
    public function testReturnsIdentityWhenIdentityIsPrincipal(): void
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity&\SineMacula\Laravel\Authentication\Contracts\Principal $identity */
        $identity = \Mockery::mock(Identity::class, Principal::class);

        $resolver = new DefaultPrincipalResolver;

        self::assertSame($identity, $resolver->resolve($identity));
    }

    /**
     * Asserts the 3D path delegates to resolveDefaultPrincipal() when the
     * identity implements HasPrincipals but not Principal itself.
     *
     * @return void
     */
    public function testDelegatesToResolveDefaultPrincipalWhenIdentityImplementsHasPrincipals(): void
    {
        $principal = \Mockery::mock(Principal::class);

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class, HasPrincipals::class);
        $identity->shouldReceive('resolveDefaultPrincipal')
            ->once()
            ->andReturn($principal);
        $identity->shouldNotReceive('principals');

        $resolver = new DefaultPrincipalResolver;

        self::assertSame($principal, $resolver->resolve($identity));
    }

    /**
     * Asserts a hint takes precedence over the default delegate when the
     * identity implements HasPrincipals: the resolver calls
     * principals()->find($hint) and returns its result.
     *
     * @return void
     */
    public function testHintTakesPrecedenceOverDefaultDelegate(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->once()
            ->with('principal-id-7')
            ->andReturn($principal);

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class, HasPrincipals::class);
        $identity->shouldReceive('principals')
            ->once()
            ->andReturn($builder);
        $identity->shouldNotReceive('resolveDefaultPrincipal');

        $resolver = new DefaultPrincipalResolver;

        self::assertSame($principal, $resolver->resolve($identity, 'principal-id-7'));
    }

    /**
     * When `principals()->find($hint)` returns a value that is NOT a
     * `Principal` (e.g. a bare Model or `null`), the resolver falls through to
     * the 2D/3D path instead of returning the non-Principal. Mutation guard:
     * pins the `$hinted instanceof Principal` check in `resolve()` -
     * removing it would cause the resolver to return a non-Principal object.
     *
     * @return void
     */
    public function testHintedNonPrincipalFallsThroughToDefaultResolution(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->once()
            ->with('non-principal-id')
            ->andReturnNull();

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity&\SineMacula\Laravel\Authentication\Contracts\Principal $identity */
        $identity = \Mockery::mock(Identity::class, HasPrincipals::class, Principal::class);
        $identity->shouldReceive('principals')
            ->once()
            ->andReturn($builder);

        $resolver = new DefaultPrincipalResolver;

        // The hint didn't resolve to a Principal, so the 2D path kicks in and
        // returns the identity itself.
        self::assertSame($identity, $resolver->resolve($identity, 'non-principal-id'));
    }

    /**
     * In 3D mode, a hinted miss falls through to `resolveDefaultPrincipal()`
     * rather than returning `null`.
     *
     * @return void
     */
    public function testHintedMissFallsThroughToDefaultPrincipalIn3dMode(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('find')
            ->once()
            ->with('missing-principal')
            ->andReturnNull();

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity $identity */
        $identity = \Mockery::mock(Identity::class, HasPrincipals::class);
        $identity->shouldReceive('principals')
            ->once()
            ->andReturn($builder);
        $identity->shouldReceive('resolveDefaultPrincipal')
            ->once()
            ->andReturn($principal);

        $resolver = new DefaultPrincipalResolver;

        self::assertSame($principal, $resolver->resolve($identity, 'missing-principal'));
    }

    /**
     * Asserts a hint is silently ignored when the identity does not implement
     * HasPrincipals; the 2D path still resolves the identity itself without
     * ever touching a principals relation.
     *
     * @return void
     */
    public function testHintIsIgnoredWhenIdentityDoesNotImplementHasPrincipals(): void
    {
        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity&\SineMacula\Laravel\Authentication\Contracts\Principal $identity */
        $identity = \Mockery::mock(Identity::class, Principal::class);

        $resolver = new DefaultPrincipalResolver;

        self::assertSame($identity, $resolver->resolve($identity, 'ignored-hint'));
    }

    /**
     * Asserts a bare Identity mock that implements neither Principal nor
     * HasPrincipals throws the typed `UnresolvableIdentityException` (a
     * `\LogicException` subclass) whose message names the offending class.
     * Guards catch this specific type and convert it to a `Failed` event so
     * the request still surfaces as a 401 - but consumer error reporters can
     * attribute the misconfiguration via the typed class.
     *
     * @return void
     */
    public function testThrowsUnresolvableIdentityExceptionWhenIdentityImplementsNeitherInterface(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $resolver = new DefaultPrincipalResolver;

        $this->expectException(UnresolvableIdentityException::class);
        $this->expectExceptionMessage($identity::class);
        $this->expectExceptionMessage('implements neither Principal nor HasPrincipals');

        $resolver->resolve($identity);
    }

    /**
     * Asserts the typed exception inherits from `\LogicException`, preserving
     * the existing exception-handler contract for consumers who catch
     * `\LogicException` broadly. Verified via a runtime instance check rather
     * than `is_subclass_of(...)` so static analysis can narrow the
     * relationship.
     *
     * @return void
     */
    public function testUnresolvableIdentityExceptionExtendsLogicException(): void
    {
        $exception = new UnresolvableIdentityException('test');

        self::assertInstanceOf(\LogicException::class, $exception);
    }
}
