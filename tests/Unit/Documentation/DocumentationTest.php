<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\ApiKeyGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;

/**
 * A drift guard for the README and the guides in docs/guides: every failure
 * reason, flow and revocation reason, every package event, every configuration
 * key and every method of the package's auth manager is documented, and every
 * `Auth::` call they show exists.
 *
 * It catches an omission or a rename, not wrong prose: what the documentation
 * says about each of them is held to the code by review.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class DocumentationTest extends TestCase
{
    /** @var list<string> Configuration maps whose keys are data the application names (kids, identifier types), documented as the map. */
    private const array DATA_MAPS = ['jwt.keys', 'identifiers.normalisers'];

    /** @var ?string The README and the guides, read once. */
    private static ?string $documentation = null;

    /**
     * Rows of `[enum value, enum]`: every failure reason, authentication flow
     * and revocation reason.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideEnumValues(): iterable
    {
        foreach ([FailureReason::class, AuthenticationFlow::class, RevocationReason::class] as $enum) {
            foreach ($enum::cases() as $case) {
                yield $enum . '::' . $case->name => [$case->value, $enum];
            }
        }
    }

    /**
     * Every failure reason, flow and revocation reason is named in the
     * documentation, in code type.
     *
     * @param  string  $value
     * @param  string  $enum
     * @return void
     */
    #[DataProvider('provideEnumValues')]
    public function testEveryEnumValueIsDocumented(string $value, string $enum): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $value . '`'), sprintf('The documentation does not name the %s value `%s`.', $enum, $value));
    }

    /**
     * Rows of `[event class]`: every event the package dispatches.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideEvents(): iterable
    {
        foreach (glob(dirname(__DIR__, 3) . '/src/Events/*.php') ?: [] as $file) {

            $class = 'SineMacula\Laravel\Authentication\Events\\' . basename($file, '.php');

            if (!is_a($class, AuthenticationEvent::class, true) || (new \ReflectionClass($class))->isAbstract()) {
                continue;
            }

            yield basename($file, '.php') => [$class];
        }
    }

    /**
     * Every event the package dispatches has a row in the events guide's
     * table.
     *
     * @param  class-string  $class
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testEveryEventIsInTheEventsTable(string $class): void
    {
        $name = (new \ReflectionClass($class))->getShortName();

        self::assertSame(1, preg_match('/^\| `SineMacula\\\\\.\.\.\\\Events\\\\' . $name . '`/m', self::documentation()), sprintf('The events table has no row for %s.', $name));
    }

    /**
     * Rows of `[key]`: every configuration key the package config ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideConfigurationKeys(): iterable
    {
        /** @var array<string, mixed> $config */
        $config = require dirname(__DIR__, 3) . '/config/authentication.php';

        foreach (self::leafKeys($config) as $key) {
            yield $key => [$key];
        }
    }

    /**
     * Every configuration key is named by its full path in the documentation.
     *
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideConfigurationKeys')]
    public function testEveryConfigurationKeyIsDocumented(string $key): void
    {
        self::assertTrue(str_contains(self::documentation(), '`' . $key . '`'), sprintf('The documentation does not name the configuration key `%s`.', $key));
    }

    /**
     * Rows of `[method]`: every public method the package's auth manager
     * declares.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideManagerMethods(): iterable
    {
        foreach ((new \ReflectionClass(AuthManager::class))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {

            if ($method->getDeclaringClass()->getName() !== AuthManager::class) {
                continue;
            }

            yield $method->getName() => [$method->getName()];
        }
    }

    /**
     * Every method the package's auth manager declares is shown being called.
     *
     * @param  string  $method
     * @return void
     */
    #[DataProvider('provideManagerMethods')]
    public function testEveryManagerMethodIsDocumented(string $method): void
    {
        self::assertSame(1, preg_match('/(::|->|`)' . $method . '\(/', self::documentation()), sprintf('The documentation does not show %s().', $method));
    }

    /**
     * Every `Auth::name(` the documentation calls is a method of the package's
     * auth manager or facade, or of the guard the facade forwards the rest to.
     *
     * @return void
     */
    public function testEveryAuthCallTheDocumentationShowsExists(): void
    {
        preg_match_all('/\bAuth::(\w+)\(/', self::documentation(), $matches);

        $unknown = [];

        foreach (array_unique($matches[1]) as $method) {

            $exists = method_exists(AuthManager::class, $method)
                || method_exists(Auth::class, $method)
                || method_exists(JwtGuard::class, $method)
                || method_exists(ApiKeyGuard::class, $method);

            if ($exists) {
                continue;
            }

            $unknown[] = $method;
        }

        self::assertSame([], $unknown, 'The documentation calls Auth methods that do not exist.');
    }

    /**
     * The dotted paths of the configuration's settings: every key whose value
     * is not a map of further settings, a list and an empty array included,
     * each data map as a whole, and each rate limit (`max` and `decay_seconds`)
     * as one setting.
     *
     * @param  array<array-key, mixed>  $config
     * @param  string  $prefix
     * @return list<string>
     */
    private static function leafKeys(array $config, string $prefix = ''): array
    {
        $keys = [];

        foreach ($config as $key => $value) {

            $path = $prefix . $key;

            if (!is_array($value) || $value === [] || array_is_list($value) || in_array($path, self::DATA_MAPS, true) || array_keys($value) === ['max', 'decay_seconds']) {
                $keys[] = $path;

                continue;
            }

            array_push($keys, ...self::leafKeys($value, $path . '.'));
        }

        return $keys;
    }

    /**
     * The text of the README and every guide.
     *
     * @return string
     */
    private static function documentation(): string
    {
        $root  = dirname(__DIR__, 3);
        $files = [$root . '/README.md', ...(glob($root . '/docs/guides/*.md') ?: [])];

        return self::$documentation ??= implode("\n", array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
    }
}
