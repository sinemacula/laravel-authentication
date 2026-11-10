<?php

declare(strict_types = 1);

namespace Tests\Unit\Support;

use Illuminate\Database\Eloquent\Relations\Relation;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Support\MorphClass;
use Tests\Unit\Stubs\StubAuthenticatableModel;
use Tests\Unit\Stubs\StubModel;

/**
 * Unit tests for the type an identity, principal or tenant is reported by: an
 * Eloquent model's morph class, any other object's class name, and the class
 * name of a model an enforced morph map leaves out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MorphClass::class)]
final class MorphClassTest extends TestCase
{
    /**
     * Forget the morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);
        Relation::requireMorphMap(false);

        parent::tearDown();
    }

    /**
     * A model is named by its morph class, its alias once the morph map gives
     * it one; any other object by its class name.
     *
     * @return void
     */
    public function testAModelIsNamedByItsMorphClassAndAnythingElseByItsClass(): void
    {
        self::assertSame(StubAuthenticatableModel::class, MorphClass::of(new StubAuthenticatableModel));

        Relation::morphMap(['stub' => StubAuthenticatableModel::class]);

        self::assertSame('stub', MorphClass::of(new StubAuthenticatableModel));
        self::assertSame(\stdClass::class, MorphClass::of(new \stdClass));
    }

    /**
     * A model an enforced morph map leaves out is named by its class name
     * rather than failing the flow that reports it.
     *
     * @return void
     */
    public function testAModelAnEnforcedMorphMapLeavesOutIsNamedByItsClass(): void
    {
        Relation::enforceMorphMap(['other' => StubModel::class]);

        self::assertSame(StubAuthenticatableModel::class, MorphClass::of(new StubAuthenticatableModel));
    }

    /**
     * The class holds no state and cannot be instantiated: its constructor is
     * private. Reflection invokes it so the line is covered while still
     * documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(MorphClass::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(MorphClass::class, $instance);
    }
}
