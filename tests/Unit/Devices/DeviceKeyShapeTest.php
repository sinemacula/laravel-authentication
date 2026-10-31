<?php

declare(strict_types = 1);

namespace Tests\Unit\Devices;

use Illuminate\Database\Eloquent\Concerns\HasUlids;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\ValidatesDeviceKey;
use SineMacula\Laravel\Authentication\Devices\DeviceKeyShape;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Unit tests for the `DeviceKeyShape` `did` pre-check.
 *
 * Each row pairs a device model with a candidate key and the expected verdict,
 * covering every key format (model-provided rule, ULID, UUID, integer, plain
 * string) and the values on either side of each rule.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceKeyShape::class)]
final class DeviceKeyShapeTest extends TestCase
{
    /** @var string A well-formed UUID v7. */
    private const string UUID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70';

    /** @var string A well-formed ULID. */
    private const string ULID = '01ARZ3NDEKTSV4RRFFQ69G5FAV';

    /**
     * Rows of `[model, key, expected]`.
     *
     * @return iterable<string, array{0: \Illuminate\Database\Eloquent\Model, 1: mixed, 2: bool}>
     */
    public static function provideKeys(): iterable
    {
        yield from [
            'uuid model accepts a uuid'                => [new Device, self::UUID, true],
            'uuid model rejects a malformed string'    => [new Device, 'not-a-uuid', false],
            'uuid model rejects a ulid'                => [new Device, self::ULID, false],
            'uuid model rejects an integer'            => [new Device, 42, false],
            'uuid model rejects null'                  => [new Device, null, false],
            'ulid model accepts a ulid'                => [self::ulidKeyModel(), self::ULID, true],
            'ulid model rejects a uuid'                => [self::ulidKeyModel(), self::UUID, false],
            'ulid model rejects an integer'            => [self::ulidKeyModel(), 7, false],
            'integer model accepts an integer'         => [self::integerKeyModel(), 5, true],
            'integer model accepts a decimal string'   => [self::integerKeyModel(), '5', true],
            'integer model accepts zero'               => [self::integerKeyModel(), '0', true],
            'integer model accepts a negative string'  => [self::integerKeyModel(), '-3', true],
            'integer model rejects a padded string'    => [self::integerKeyModel(), '007', false],
            'integer model rejects whitespace'         => [self::integerKeyModel(), ' 5', false],
            'integer model rejects a plus sign'        => [self::integerKeyModel(), '+5', false],
            'integer model rejects a decimal fraction' => [self::integerKeyModel(), '5.0', false],
            'integer model rejects an overflow'        => [self::integerKeyModel(), '99999999999999999999', false],
            'integer model rejects text'               => [self::integerKeyModel(), 'abc', false],
            'integer model rejects a float'            => [self::integerKeyModel(), 5.0, false],
            'integer model rejects a boolean'          => [self::integerKeyModel(), true, false],
            'integer alias model accepts an integer'   => [self::integerAliasKeyModel(), '5', true],
            'integer alias model rejects text'         => [self::integerAliasKeyModel(), 'abc', false],
            'string model accepts a string'            => [self::stringKeyModel(), 'device-1', true],
            'string model rejects an empty string'     => [self::stringKeyModel(), '', false],
            'string model rejects an integer'          => [self::stringKeyModel(), 5, false],
            'non-key uuid column keeps integer rule'   => [self::uuidColumnModel(), '5', true],
            'non-key uuid column rejects a uuid key'   => [self::uuidColumnModel(), self::UUID, false],
            'non-key ulid column keeps integer rule'   => [self::ulidColumnModel(), '5', true],
            'non-key ulid column rejects a ulid key'   => [self::ulidColumnModel(), self::ULID, false],
            'model rule accepts its own format'        => [self::customRuleModel(), 'custom-7', true],
            'model rule overrides the uuid rule'       => [self::customRuleModel(), self::UUID, false],
        ];
    }

    /**
     * Asserts the verdict for one model and candidate key.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  mixed  $key
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideKeys')]
    public function testMatchesReportsWhetherTheValueCanBeTheModelKey(Model $model, mixed $key, bool $expected): void
    {
        self::assertSame($expected, DeviceKeyShape::matches($model, $key));
    }

    /**
     * `DeviceKeyShape` is a static utility; instantiation is disallowed via the
     * private constructor so consumers cannot create a stateful device-key
     * shape check. Reflection invokes the private constructor so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(DeviceKeyShape::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(DeviceKeyShape::class, $instance);
    }

    /**
     * A model whose primary key is a generated ULID.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function ulidKeyModel(): Model
    {
        return new class extends Model {
            use HasUlids;
        };
    }

    /**
     * A model with Laravel's default auto-incrementing integer key.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function integerKeyModel(): Model
    {
        return new class extends Model {};
    }

    /**
     * A model that spells its integer key type `integer`.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function integerAliasKeyModel(): Model
    {
        return new class extends Model {
            /** @var string The primary key type. */
            protected $keyType = 'integer';
        };
    }

    /**
     * A model with a plain string key and no generated ids.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function stringKeyModel(): Model
    {
        return new class extends Model {
            /** @var bool Whether the primary key auto-increments. */
            public $incrementing = false;

            /** @var string The primary key type. */
            protected $keyType = 'string';
        };
    }

    /**
     * A model with an integer key that generates a UUID for another column.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function uuidColumnModel(): Model
    {
        return new class extends Model {
            use HasUuids;

            /**
             * Columns that receive a generated unique identifier on insert.
             *
             * @return array<int, string>
             */
            #[\Override]
            public function uniqueIds(): array
            {
                return ['public_id'];
            }
        };
    }

    /**
     * A model with an integer key that generates a ULID for another column.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function ulidColumnModel(): Model
    {
        return new class extends Model {
            use HasUlids;

            /**
             * Columns that receive a generated unique identifier on insert.
             *
             * @return array<int, string>
             */
            #[\Override]
            public function uniqueIds(): array
            {
                return ['public_id'];
            }
        };
    }

    /**
     * A UUID-keyed model that supplies its own key rule.
     *
     * @return \Illuminate\Database\Eloquent\Model
     */
    private static function customRuleModel(): Model
    {
        return new class extends Model implements ValidatesDeviceKey {
            use HasUuids;

            /**
             * Accept only `custom-` prefixed keys.
             *
             * @param  mixed  $key
             * @return bool
             */
            #[\Override]
            public function isValidDeviceKey(mixed $key): bool
            {
                return is_string($key) && str_starts_with($key, 'custom-');
            }
        };
    }
}
