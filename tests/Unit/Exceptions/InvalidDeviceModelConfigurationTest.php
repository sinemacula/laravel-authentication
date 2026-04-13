<?php

declare(strict_types = 1);

namespace Tests\Unit\Exceptions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfiguration;
use Tests\Unit\Stubs\StubBareDevice;
use Tests\Unit\Stubs\StubDevice;

/**
 * Unit tests for the InvalidDeviceModelConfiguration exception.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(InvalidDeviceModelConfiguration::class)]
final class InvalidDeviceModelConfigurationTest extends TestCase
{
    /**
     * `validate()` passes silently for a valid EloquentDevice model.
     *
     * @return void
     */
    public function testValidatePassesForValidEloquentDeviceModel(): void
    {
        InvalidDeviceModelConfiguration::validate(StubDevice::class);

        self::assertTrue(true, 'validate() did not throw for a valid device model.');
    }

    /**
     * `validate()` throws for an empty class string.
     *
     * @return void
     */
    public function testValidateThrowsForEmptyString(): void
    {
        $this->expectException(InvalidDeviceModelConfiguration::class);
        $this->expectExceptionMessage('(empty string)');

        InvalidDeviceModelConfiguration::validate('');
    }

    /**
     * `validate()` throws for a nonexistent class.
     *
     * @return void
     */
    public function testValidateThrowsForNonexistentClass(): void
    {
        $this->expectException(InvalidDeviceModelConfiguration::class);
        $this->expectExceptionMessage('App\Models\FakeDevice');

        InvalidDeviceModelConfiguration::validate('App\Models\FakeDevice');
    }

    /**
     * `validate()` throws for a class that is not an Eloquent model.
     *
     * @return void
     */
    public function testValidateThrowsForNonModelClass(): void
    {
        $this->expectException(InvalidDeviceModelConfiguration::class);

        InvalidDeviceModelConfiguration::validate(\stdClass::class);
    }

    /**
     * `validate()` throws for a Model that does not implement EloquentDevice.
     *
     * @return void
     */
    public function testValidateThrowsForModelWithoutEloquentDevice(): void
    {
        $this->expectException(InvalidDeviceModelConfiguration::class);

        InvalidDeviceModelConfiguration::validate(StubBareDevice::class);
    }

    /**
     * `unsupported()` builds an exception with the configured class in the
     * message.
     *
     * @return void
     */
    public function testUnsupportedIncludesConfiguredClassInMessage(): void
    {
        $exception = InvalidDeviceModelConfiguration::unsupported('App\BadDevice');

        self::assertStringContainsString('App\BadDevice', $exception->getMessage());
        self::assertStringContainsString(
            EloquentDevice::class,
            $exception->getMessage(),
        );
    }

    /**
     * `unsupported()` substitutes `(empty string)` when the configured class is
     * empty.
     *
     * @return void
     */
    public function testUnsupportedDisplaysEmptyStringPlaceholder(): void
    {
        $exception = InvalidDeviceModelConfiguration::unsupported('');

        self::assertStringContainsString('(empty string)', $exception->getMessage());
    }
}
