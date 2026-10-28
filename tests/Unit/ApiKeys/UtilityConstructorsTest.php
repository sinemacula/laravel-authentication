<?php

declare(strict_types = 1);

namespace Tests\Unit\ApiKeys;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyRules;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySettings;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyToken;
use SineMacula\Laravel\Authentication\ApiKeys\CredentialBinding;

/**
 * The API key utility classes hold no state and cannot be instantiated: each
 * constructor is private. Reflection invokes it so the line is covered while
 * still documenting the access modifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApiKeyLookup::class)]
#[CoversClass(ApiKeyRules::class)]
#[CoversClass(ApiKeySettings::class)]
#[CoversClass(ApiKeyToken::class)]
#[CoversClass(CredentialBinding::class)]
final class UtilityConstructorsTest extends TestCase
{
    /**
     * Rows of `[class]`: the utility classes.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideUtilities(): iterable
    {
        yield from [
            'lookup'   => [ApiKeyLookup::class],
            'rules'    => [ApiKeyRules::class],
            'settings' => [ApiKeySettings::class],
            'token'    => [ApiKeyToken::class],
            'binding'  => [CredentialBinding::class],
        ];
    }

    /**
     * The constructor is private.
     *
     * @param  class-string  $class
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    #[DataProvider('provideUtilities')]
    public function testConstructorIsPrivate(string $class): void
    {
        $reflection  = new \ReflectionClass($class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf($class, $instance);
    }
}
