<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Guards\Concerns\BindsContextualState;

/**
 * Holds the package to keeping no request, identity or token state in a static,
 * which a long-lived worker would carry into the next request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class StaticStateTest extends TestCase
{
    /**
     * The only static property is the guards' integer version counter.
     *
     * @return void
     */
    public function testTheOnlyStaticPropertyIsTheBoundStateVersionCounter(): void
    {
        $properties = [];

        foreach (array_keys(self::sources()) as $class) {

            self::assertTrue(class_exists($class) || trait_exists($class) || interface_exists($class) || enum_exists($class), $class);

            $reflection = new \ReflectionClass($class);
            $traits     = $reflection->getTraits();

            foreach ($reflection->getProperties(\ReflectionProperty::IS_STATIC) as $property) {

                $name      = $property->getName();
                $declarer  = $property->getDeclaringClass()->getName();
                $fromTrait = array_filter($traits, static fn (\ReflectionClass $trait): bool => $trait->hasProperty($name)) !== [];

                if ($declarer !== $class || $fromTrait) {
                    continue;
                }

                $properties[$class . '::$' . $name] = (string) $property->getType();
            }
        }

        self::assertSame([BindsContextualState::class . '::$boundStateVersions' => 'int'], $properties);
    }

    /**
     * No function, method or closure declares a static variable.
     *
     * @return void
     */
    public function testNoFunctionDeclaresAStaticVariable(): void
    {
        $variables = [];

        foreach (self::sources() as $class => $file) {

            $tokens = array_values(array_filter(
                \PhpToken::tokenize((string) file_get_contents($file)),
                static fn (\PhpToken $token): bool => !$token->isIgnorable(),
            ));

            foreach ($tokens as $index => $token) {

                $next = $tokens[$index + 1] ?? null;

                if (!$token->is(T_STATIC) || $next?->is(T_VARIABLE) !== true) {
                    continue;
                }

                $variables[] = $class . ' declares static ' . $next->text;
            }
        }

        self::assertSame([], $variables);
    }

    /**
     * Every class, trait, interface and enum under `src`, with its file.
     *
     * @return array<string, string>
     */
    private static function sources(): array
    {
        $source  = dirname(__DIR__, 3) . '/src/';
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));
        $sources = [];

        foreach ($files as $file) {

            assert($file instanceof \SplFileInfo);

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $sources['SineMacula\Laravel\Authentication\\' . str_replace('/', '\\', substr($file->getPathname(), strlen($source), -4))] = $file->getPathname();
        }

        self::assertNotEmpty($sources);

        return $sources;
    }
}
