<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Database\Eloquent\Relations\Relation;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;
use Tests\TestCase;
use Tests\Unit\Stubs\StubDevice;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for how a principal is recorded on a device.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalReference::class)]
final class PrincipalReferenceTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Forget any morph map a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Relation::morphMap([], false);

        parent::tearDown();
    }

    /**
     * An Eloquent principal is recorded by its morph class, which a morph map
     * may alias; any other principal by its class name.
     *
     * @return void
     */
    public function testTheTypeIsTheMorphClassOrTheClassName(): void
    {
        $plain = \Mockery::mock(Principal::class);

        self::assertSame(StubPrincipal::class, PrincipalReference::type(new StubPrincipal));
        self::assertSame($plain::class, PrincipalReference::type($plain));

        Relation::morphMap(['member' => StubPrincipal::class]);

        self::assertSame('member', PrincipalReference::type(new StubPrincipal));
    }

    /**
     * The identifier is recorded as a string, and a principal without one
     * (unsaved) records none.
     *
     * @return void
     */
    public function testTheIdentifierIsRecordedAsAString(): void
    {
        $saved = (new StubPrincipal)->forceFill(['id' => 7]);

        self::assertSame('7', PrincipalReference::id($saved));
        self::assertNull(PrincipalReference::id(new StubPrincipal));
    }

    /**
     * A device records a principal when both its principal columns name it;
     * another type, another identifier, or a device recording none does not.
     *
     * @return void
     */
    public function testADeviceRecordsThePrincipalOnlyByTypeAndIdentifier(): void
    {
        $principal = (new StubPrincipal)->forceFill(['id' => 7]);

        self::assertTrue(PrincipalReference::isRecordedOn($this->device(StubPrincipal::class, '7'), $principal));
        self::assertFalse(PrincipalReference::isRecordedOn($this->device('other', '7'), $principal));
        self::assertFalse(PrincipalReference::isRecordedOn($this->device(StubPrincipal::class, '8'), $principal));
        self::assertFalse(PrincipalReference::isRecordedOn($this->device(null, null), $principal));
        self::assertFalse(PrincipalReference::isRecordedOn($this->device(StubPrincipal::class, null), new StubPrincipal));

        $plain = \Mockery::mock(Principal::class);
        $plain->shouldReceive('getPrincipalIdentifier')->andReturn('p-1');

        self::assertTrue(PrincipalReference::isRecordedOn($this->device($plain::class, 'p-1'), $plain));
    }

    /**
     * The principal columns are the device's `principal()` relation's, read
     * without instantiating the type a device records.
     *
     * @return void
     */
    public function testTheColumnsAreThePrincipalRelations(): void
    {
        self::assertSame(['principal_type', 'principal_id'], PrincipalReference::columns($this->device('not-a-class', '7')));
    }

    /**
     * `PrincipalReference` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PrincipalReference::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PrincipalReference::class, $instance);
    }

    /**
     * Build a device recording the principal columns.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @return \Tests\Unit\Stubs\StubDevice
     */
    private function device(?string $type, ?string $id): StubDevice
    {
        return (new StubDevice)->forceFill(['principal_type' => $type, 'principal_id' => $id]);
    }
}
