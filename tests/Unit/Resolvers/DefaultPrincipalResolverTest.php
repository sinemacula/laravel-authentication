<?php

declare(strict_types = 1);

namespace Tests\Unit\Resolvers;

use Illuminate\Contracts\Database\Eloquent\Builder;
use LogicException;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\HasPrincipals;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;

/**
 * Unit tests for the DefaultPrincipalResolver.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class DefaultPrincipalResolverTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Asserts the 2D path returns the identity itself when it also
     * implements the Principal contract.
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
     * Asserts a hint is silently ignored when the identity does not
     * implement HasPrincipals; the 2D path still resolves the identity
     * itself without ever touching a principals relation.
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
     * HasPrincipals throws a LogicException whose message names the
     * offending class.
     *
     * @return void
     */
    public function testThrowsLogicExceptionWhenIdentityImplementsNeitherInterface(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $resolver = new DefaultPrincipalResolver;

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage($identity::class);
        $this->expectExceptionMessage('implements neither Principal nor HasPrincipals');

        $resolver->resolve($identity);
    }
}
