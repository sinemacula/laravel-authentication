<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\Relation;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;
use Tests\Unit\Stubs\Stub3dPrincipal;

/**
 * Feature tests for proving that a principal someone else named belongs to an
 * identity: the resolver's hinted path must return a principal of the same
 * class and identifier, owned by the identity as its own stored key says.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PinnedPrincipal::class)]
final class PinnedPrincipalTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The resolver the pin goes through. */
    private MockInterface $resolver;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity The identity the pin must belong to. */
    private MockInterface $identity;

    /**
     * Build the resolver and an identity with identifier 7.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->identity = \Mockery::mock(Identity::class);
        $this->identity->shouldReceive('getAuthIdentifier')->andReturn(7);
    }

    /**
     * A pin the identity owns resolves through the hinted path to the
     * resolver's own instance.
     *
     * @return void
     */
    public function testAnOwnedPinResolvesToTheResolversInstance(): void
    {
        $pinned   = $this->principal('p-1');
        $resolved = $this->principal('p-1', $this->identity);

        $this->resolver->shouldReceive('resolve')->once()->with($this->identity, 'p-1')->andReturn($resolved);

        self::assertSame($resolved, PinnedPrincipal::resolve($this->resolver, $this->identity, $pinned));
    }

    /**
     * Nothing resolved, another principal (the resolver's fallback), or one of
     * another class with the same identifier, does not prove the pin.
     *
     * @return void
     */
    public function testAPinTheResolverDoesNotReturnExactlyIsRefused(): void
    {
        $pinned = $this->principal('p-1');
        $other  = \Mockery::mock(Principal::class, HasDevices::class);
        $other->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');

        $this->resolver->shouldReceive('resolve')->with($this->identity, 'p-1')->andReturn(null, $this->principal('p-2', $this->identity), $other);

        self::assertNull(PinnedPrincipal::resolve($this->resolver, $this->identity, $pinned));
        self::assertNull(PinnedPrincipal::resolve($this->resolver, $this->identity, $pinned));
        self::assertNull(PinnedPrincipal::resolve($this->resolver, $this->identity, $pinned));
    }

    /**
     * A pin without an identifier (unsaved) is asked of the resolver without a
     * hint and can never match.
     *
     * @return void
     */
    public function testAPinWithoutAnIdentifierIsRefused(): void
    {
        $pinned = $this->principal(null, $this->identity);

        $this->resolver->shouldReceive('resolve')->once()->with($this->identity)->andReturn($pinned);

        self::assertNull(PinnedPrincipal::resolve($this->resolver, $this->identity, $pinned));
    }

    /**
     * A principal is owned only by the same class of identity with the same
     * identifier; one whose owner cannot be read is not owned.
     *
     * @return void
     */
    public function testOwnershipNeedsTheSameClassAndIdentifier(): void
    {
        $victim = \Mockery::mock(Identity::class);
        $victim->shouldReceive('getAuthIdentifier')->andReturn(8);

        $otherClass = \Mockery::mock(Identity::class, HasDevices::class);
        $otherClass->shouldReceive('getAuthIdentifier')->andReturn(7);

        $unreadable = $this->principal('p-1');
        $unreadable->shouldReceive('getIdentity')->andThrow(new \LogicException('The owner cannot be loaded.'));

        self::assertTrue(PinnedPrincipal::isOwnedBy($this->principal('p-1', $this->identity), $this->identity));
        self::assertFalse(PinnedPrincipal::isOwnedBy($this->principal('p-1', $victim), $this->identity));
        self::assertFalse(PinnedPrincipal::isOwnedBy($this->principal('p-1', $otherClass), $this->identity));
        self::assertFalse(PinnedPrincipal::isOwnedBy($unreadable, $this->identity));
    }

    /**
     * An Eloquent principal's owner is read from its own stored key, even when
     * lazy loading is prevented, and an identity relation already set on it
     * does not vouch for it.
     *
     * @return void
     */
    public function testAnEloquentPrincipalsOwnerIsReadFromItsStoredKey(): void
    {
        $owner = \Mockery::mock(BelongsTo::class);
        $owner->shouldReceive('getResults')->once()->andReturn($this->identity);

        $owned = new class extends Stub3dPrincipal {};

        $owned::resolveRelationUsing('identity', static fn (): Relation => $owner);

        $owned->forceFill(['id' => 5]);
        $owned->exists              = true;
        $owned->preventsLazyLoading = true;

        self::assertTrue(PinnedPrincipal::isOwnedBy($owned, $this->identity));

        $vouched = new Stub3dPrincipal;
        $vouched->forceFill(['id' => 5]);
        $vouched->setRelation('identity', $this->identity);

        self::assertFalse(PinnedPrincipal::isOwnedBy($vouched, $this->identity));
    }

    /**
     * `PinnedPrincipal` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PinnedPrincipal::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * Build a principal with the identifier, owned by the identity when one is
     * given.
     *
     * @param  ?string  $identifier
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private function principal(?string $identifier, ?Identity $owner = null): MockInterface
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn($identifier);

        if ($owner !== null) {
            $principal->shouldReceive('getIdentity')->andReturn($owner);
        }

        return $principal;
    }
}
