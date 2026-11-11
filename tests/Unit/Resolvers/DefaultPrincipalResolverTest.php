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
use SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal;
use SineMacula\Laravel\Authentication\Resolvers\DefaultPrincipalResolver;
use SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException;

/**
 * Unit tests for the DefaultPrincipalResolver.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DefaultPrincipalResolver::class)]
final class DefaultPrincipalResolverTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The identity is its own principal when it implements `Principal`.
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
     * An identity with principals resolves its default principal.
     *
     * @return void
     */
    public function testHasPrincipalsIdentityResolvesItsDefaultPrincipal(): void
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
     * A hint is looked up through `principals()->find()` before the default.
     *
     * @return void
     */
    public function testHintTakesPrecedenceOverDefaultDelegate(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
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
     * `ResolvesHintedPrincipal` is preferred over `principals()->find()`.
     *
     * @return void
     */
    public function testHintedLookupPrefersResolveHintedPrincipalCapability(): void
    {
        $principal = \Mockery::mock(Principal::class);

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity&\SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal $identity */
        $identity = \Mockery::mock(Identity::class, ResolvesHintedPrincipal::class, HasPrincipals::class);
        $identity->shouldReceive('resolveHintedPrincipal')
            ->once()
            ->with('principal-id-9')
            ->andReturn($principal);
        $identity->shouldNotReceive('principals');
        $identity->shouldNotReceive('resolveDefaultPrincipal');

        $resolver = new DefaultPrincipalResolver;

        self::assertSame($principal, $resolver->resolve($identity, 'principal-id-9'));
    }

    /**
     * A hinted lookup that finds no `Principal` falls through to the default.
     *
     * @return void
     */
    public function testHintedNonPrincipalFallsThroughToDefaultResolution(): void
    {
        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
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
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
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
     * A null from `resolveHintedPrincipal()` falls back to
     * `principals()->find()` and then the default principal.
     *
     * @return void
     */
    public function testNullHintedPrincipalFallsBackToTheRelation(): void
    {
        $principal = \Mockery::mock(Principal::class);

        $builder = \Mockery::mock(Builder::class);
        $builder->shouldReceive('useWritePdo')
            ->once()
            ->andReturnSelf();
        $builder->shouldReceive('find')
            ->once()
            ->with('missing-principal')
            ->andReturnNull();

        /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\HasPrincipals&\SineMacula\Laravel\Authentication\Contracts\Identity&\SineMacula\Laravel\Authentication\Contracts\ResolvesHintedPrincipal $identity */
        $identity = \Mockery::mock(Identity::class, ResolvesHintedPrincipal::class, HasPrincipals::class);
        $identity->shouldReceive('resolveHintedPrincipal')
            ->once()
            ->with('missing-principal')
            ->andReturnNull();
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
     * A hint is ignored when the identity does not implement `HasPrincipals`.
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
     * An identity with neither `Principal` nor `HasPrincipals` is refused with
     * an exception naming its class.
     *
     * @return void
     */
    public function testIdentityWithNeitherContractIsUnresolvable(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $resolver = new DefaultPrincipalResolver;

        $this->expectException(UnresolvableIdentityException::class);
        $this->expectExceptionMessage($identity::class);
        $this->expectExceptionMessage('implements neither Principal nor HasPrincipals');

        $resolver->resolve($identity);
    }

    /**
     * `UnresolvableIdentityException` is a `\LogicException`.
     *
     * @return void
     */
    public function testUnresolvableIdentityExceptionExtendsLogicException(): void
    {
        $exception = new UnresolvableIdentityException('test');

        self::assertInstanceOf(\LogicException::class, $exception);
    }
}
