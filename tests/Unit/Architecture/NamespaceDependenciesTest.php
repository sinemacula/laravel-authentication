<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Holds the package's namespaces to the dependency rules its design states:
 * which classes may not name which others. Each rule is data in `RULES`, so a
 * change that moves a class or narrows a dependency adds or tightens a rule
 * there. A rule applies to the classes in its `from` namespaces or classes (`*`
 * for every class of the package) except those in `except`, and forbids them to
 * name anything in its `forbids` namespaces or classes except what `allows`
 * lists; every name is relative to the package.
 *
 * A class names another through an import (`use`, grouped or aliased), a
 * qualified or fully qualified name in its code, or a fully qualified type in a
 * docblock. The source is tokenised, not parsed, so a name built at run time (a
 * class name in a string, say) and an unqualified name of a class in the same
 * namespace are not seen: the test is a backstop for the rules, not a proof of
 * them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class NamespaceDependenciesTest extends TestCase
{
    /** @var string The namespace every name below is relative to. */
    private const string PACKAGE = 'SineMacula\Laravel\Authentication\\';

    /** @var string A fully qualified package name in a docblock. */
    private const string DOCBLOCK_NAME = '/\\\(SineMacula\\\Laravel\\\Authentication\\\[A-Za-z0-9_\\\]+)/';

    /** @var array<string, array{from: non-empty-list<string>, except: list<string>, forbids: non-empty-list<string>, allows: list<string>}> The rules, by what each holds. */
    private const array RULES = [
        'models name nothing of tokens, sessions or guards' => [
            'from'    => ['Models'],
            'except'  => [],
            'forbids' => ['Jwt', 'Sessions', 'Guards'],
            'allows'  => [],
        ],
        'storage, configuration and attempt limiting name nothing of tokens, sessions or guards' => [
            'from'    => ['Config', 'Database', 'RateLimiting'],
            'except'  => [],
            'forbids' => ['Jwt', 'Sessions', 'Guards'],
            'allows'  => [],
        ],
        'identifiers, factors, scopes, resolvers, providers, casts, delivery and verification name nothing of tokens, sessions or guards' => [
            'from'    => ['Casts', 'Delivery', 'Factors', 'Identifiers', 'Providers', 'Resolvers', 'Scopes', 'Verification'],
            'except'  => [],
            'forbids' => ['Jwt', 'Sessions', 'Guards'],
            'allows'  => [],
        ],
        'the HTTP helpers name nothing of sessions or guards' => [
            'from'    => ['Http'],
            'except'  => [],
            'forbids' => ['Sessions', 'Guards'],
            'allows'  => [],
        ],
        'contracts and events name no guard' => [
            'from'    => ['Contracts', 'Events'],
            'except'  => [],
            'forbids' => ['Guards'],
            'allows'  => [],
        ],
        'only the testing helpers name the testing helpers' => [
            'from'    => ['*'],
            'except'  => ['Testing'],
            'forbids' => ['Testing'],
            'allows'  => [],
        ],
    ];

    /** @var ?array<string, list<string>> Every class of the package and the package names it names, read once. */
    private static ?array $names = null;

    /**
     * Rows of `[from, except, forbids, allows]`: each rule.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: list<string>, 3: list<string>}>
     */
    public static function provideRules(): iterable
    {
        foreach (self::RULES as $rule => $scope) {
            yield $rule => [$scope['from'], $scope['except'], $scope['forbids'], $scope['allows']];
        }
    }

    /**
     * No class a rule applies to names anything it forbids.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testNoClassNamesWhatItsRuleForbids(array $from, array $except, array $forbids, array $allows): void
    {
        $violations = [];

        foreach (self::names() as $class => $names) {

            if (!self::isWithin($class, $from) || self::isWithin($class, $except)) {
                continue;
            }

            foreach ($names as $name) {

                if (!self::isWithin($name, $forbids) || self::isWithin($name, $allows)) {
                    continue;
                }

                $violations[] = "{$class} names {$name}";
            }
        }

        self::assertSame([], $violations);
    }

    /**
     * Every namespace or class a rule names has a class in it, so a rule left
     * behind by a move fails rather than holding over nothing.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testEveryNameARuleGivesExists(array $from, array $except, array $forbids, array $allows): void
    {
        $classes = array_keys(self::names());

        foreach ([...$from, ...$except, ...$forbids, ...$allows] as $named) {
            self::assertNotSame([], array_filter($classes, static fn (string $class): bool => self::isWithin($class, [$named])), "No class of the package is in {$named}.");
        }
    }

    /**
     * The scanner finds a package name however a class names it: imported
     * alone, aliased, grouped, as a function or a constant (alone or within a
     * group), through an alias or relative to its namespace, fully qualified in
     * code or in a docblock; and nothing for an unqualified name, a closure's
     * `use`, or a name outside the package.
     *
     * @return void
     */
    public function testTheScannerFindsEveryWayOfNamingAClass(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Authentication\Sessions;

            use Illuminate\Support\Str;
            use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
            use SineMacula\Laravel\Authentication\Guards as Guarding;
            use SineMacula\Laravel\Authentication\Events\{AuthenticationFailed, Enums\FailureReason as Reason};
            use function SineMacula\Laravel\Authentication\Support\helper;
            use SineMacula\Laravel\Authentication\{function Jwt\issue, const Guards\FLAG};

            /**
             * @see \SineMacula\Laravel\Authentication\Http\ClientContext
             */
            final class Example
            {
                use Concerns\ManagesDevices;

                /** @var \SineMacula\Laravel\Authentication\Models\Device */
                private $device;

                public function run(): void
                {
                    $value = 1;

                    $callback = static function () use ($value): int {
                        return $value;
                    };

                    new Guarding\JwtGuard;
                    new \SineMacula\Laravel\Authentication\Database\AfterCommit($callback);
                    new namespace\SessionWriter;
                    new SignInResult;
                    Str::random();
                }
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Database\AfterCommit',
            'Events\AuthenticationFailed',
            'Events\Enums\FailureReason',
            'Guards',
            'Guards\FLAG',
            'Guards\JwtGuard',
            'Http\ClientContext',
            'Jwt\TokenLifetimes',
            'Jwt\issue',
            'Models\Device',
            'Sessions\Concerns\ManagesDevices',
            'Sessions\SessionWriter',
            'Support\helper',
        ], $names);
    }

    /**
     * The scanner reads the imports of a bracketed namespace as imports, gives
     * each namespace its own aliases, reads a closure's `use` at the top of a
     * namespace as code, and resolves names in the global namespace from its
     * root.
     *
     * @return void
     */
    public function testTheScannerReadsEachBracketedNamespaceOnItsOwn(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Authentication\Models {

                use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
                use SineMacula\Laravel\Authentication\Guards as Guarding;

                $resolve = static function () use ($container): void {
                    new \SineMacula\Laravel\Authentication\Sessions\SessionService;
                };

                final class Example
                {
                    use Concerns\HasDevices;
                }
            }

            namespace {

                new Guarding\JwtGuard;
                new SineMacula\Laravel\Authentication\Database\AfterCommit;
                new namespace\SineMacula\Laravel\Authentication\Config\IntegerSetting;
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Config\IntegerSetting',
            'Database\AfterCommit',
            'Guards',
            'Jwt\TokenLifetimes',
            'Models\Concerns\HasDevices',
            'Sessions\SessionService',
        ], $names);
    }

    /**
     * Every class of the package and the package names it names, relative to
     * the package, read once.
     *
     * @return array<string, list<string>>
     */
    private static function names(): array
    {
        if (self::$names !== null) {
            return self::$names;
        }

        $source = dirname(__DIR__, 3) . '/src/';
        $files  = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));
        $names  = [];

        foreach ($files as $file) {

            assert($file instanceof \SplFileInfo);

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $class = str_replace('/', '\\', substr($file->getPathname(), strlen($source), -4));

            $names[$class] = self::namesIn((string) file_get_contents($file->getPathname()));
        }

        ksort($names);

        return self::$names = $names;
    }

    /**
     * The distinct package names the source names, relative to the package.
     *
     * An import is read as one statement, so its names are not read again as
     * names in code; each namespace's body, whether it ends at the next
     * `namespace` or at its closing brace, has its own aliases. The names of a
     * trait's or a closure's `use` are read as names in code.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function namesIn(string $source): array
    {
        $tokens    = self::tokens($source);
        $depths    = self::depths($tokens);
        $namespace = '';
        $body      = 0;
        $aliases   = [];
        $names     = [];

        for ($index = 0, $count = count($tokens); $index < $count; $index++) {

            [$id, $text] = is_array($tokens[$index]) ? $tokens[$index] : [null, $tokens[$index]];

            if ($id === T_NAMESPACE) {
                [$namespace, $body, $index] = self::declared($tokens, $depths, $index);

                $aliases = [];
            } elseif ($id === T_USE && self::isImport($tokens, $depths, $index, $body)) {
                [$statement, $index] = self::statement($tokens, $index + 1);

                array_push($names, ...self::imports($statement, $aliases));
            } elseif ($id === T_DOC_COMMENT) {
                array_push($names, ...self::documented($text));
            } elseif ($id !== null) {
                $names[] = self::qualified($id, $text, $namespace, $aliases);
            }
        }

        $package = array_filter($names, static fn (?string $name): bool => $name !== null && str_starts_with($name, self::PACKAGE));

        return array_values(array_unique(array_map(static fn (string $name): string => substr($name, strlen(self::PACKAGE)), $package)));
    }

    /**
     * The namespace declared at the index, the depth of the braces its imports
     * sit in, and the index of its last token before its body.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @return array{0: string, 1: int, 2: int}
     */
    private static function declared(array $tokens, array $depths, int $index): array
    {
        $namespace = is_array($tokens[$index + 1]) ? self::text($tokens[++$index]) : '';
        $body      = ($tokens[$index + 1] ?? null) === '{' ? $depths[$index] + 1 : $depths[$index];

        return [$namespace, $body, $index];
    }

    /**
     * Whether the `use` at the index is an import: one directly in the
     * namespace's body, not a trait's in a class or a closure's after its
     * parameters.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @param  int  $body
     * @return bool
     */
    private static function isImport(array $tokens, array $depths, int $index, int $body): bool
    {
        return $depths[$index] === $body && $tokens[$index - 1] !== ')';
    }

    /**
     * The source's tokens, without whitespace and plain comments.
     *
     * @param  string  $source
     * @return list<array{0: int, 1: string, 2: int}|string>
     */
    private static function tokens(string $source): array
    {
        $meaningful = static fn (array|string $token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT], true);

        return array_values(array_filter(token_get_all($source), $meaningful));
    }

    /**
     * How many braces are open before each token.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @return list<int>
     */
    private static function depths(array $tokens): array
    {
        $depths = [];
        $depth  = 0;

        foreach ($tokens as $token) {

            $depths[] = $depth;

            $depth += match (true) {
                $token === '{', is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true) => 1,
                $token === '}'                                                                                            => -1,
                default                                                                                                   => 0,
            };
        }

        return $depths;
    }

    /**
     * The import statement that starts at the index, as text without its
     * whitespace, and the index of its `;`.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return array{0: string, 1: int}
     */
    private static function statement(array $tokens, int $index): array
    {
        $statement = '';

        for (; ($tokens[$index] ?? ';') !== ';'; $index++) {
            $statement .= self::text($tokens[$index]);
        }

        return [$statement, $index];
    }

    /**
     * The text of the token, with a space around `as` and after `function` or
     * `const`, the words an import statement may hold.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @return string
     */
    private static function text(array|string $token): string
    {
        if (!is_array($token)) {
            return $token;
        }

        return match ($token[0]) {
            T_AS                => ' as ',
            T_FUNCTION, T_CONST => $token[1] . ' ',
            default             => $token[1],
        };
    }

    /**
     * The names an import statement imports, recording each alias it gives.
     *
     * @param  string  $statement
     * @param  array<string, string>  $aliases
     * @return list<string>
     */
    private static function imports(string $statement, array &$aliases): array
    {
        $statement = self::withoutKind($statement);
        $prefix    = '';

        if (preg_match('/^(.*)\\\\\{(.*)\}$/', $statement, $group) === 1) {
            [, $prefix, $statement] = $group;

            $prefix .= '\\';
        }

        $names = [];

        foreach (explode(',', $statement) as $import) {

            $parts = explode(' as ', self::withoutKind($import));
            $name  = ltrim($prefix . $parts[0], '\\');
            $alias = $parts[1] ?? substr((string) strrchr('\\' . $name, '\\'), 1);

            $aliases[$alias] = $name;
            $names[]         = $name;
        }

        return $names;
    }

    /**
     * The import without the `function` or `const` that may start it: a whole
     * statement's, or one member's of a group.
     *
     * @param  string  $import
     * @return string
     */
    private static function withoutKind(string $import): string
    {
        return (string) preg_replace('/^(function|const) /', '', $import);
    }

    /**
     * The fully qualified name a name token stands for: a qualified name
     * through the alias its first segment names, or else relative to the
     * namespace; `null` for any other token.
     *
     * @param  int  $id
     * @param  string  $text
     * @param  string  $namespace
     * @param  array<string, string>  $aliases
     * @return ?string
     */
    private static function qualified(int $id, string $text, string $namespace, array $aliases): ?string
    {
        if ($id === T_NAME_FULLY_QUALIFIED) {
            return substr($text, 1);
        }

        if ($id === T_NAME_RELATIVE) {
            return ltrim($namespace . substr($text, strlen('namespace')), '\\');
        }

        if ($id !== T_NAME_QUALIFIED) {
            return null;
        }

        [$first, $rest] = explode('\\', $text, 2);

        return isset($aliases[$first]) ? $aliases[$first] . '\\' . $rest : ltrim($namespace . '\\' . $text, '\\');
    }

    /**
     * The fully qualified package names a docblock gives.
     *
     * @param  string  $docblock
     * @return list<string>
     */
    private static function documented(string $docblock): array
    {
        preg_match_all(self::DOCBLOCK_NAME, $docblock, $matches);

        return array_map(static fn (string $name): string => rtrim($name, '\\'), $matches[1]);
    }

    /**
     * Whether the name is one of the namespaces or classes, or inside one of
     * them; `*` stands for the whole package.
     *
     * @param  string  $name
     * @param  list<string>  $scopes
     * @return bool
     */
    private static function isWithin(string $name, array $scopes): bool
    {
        foreach ($scopes as $scope) {
            if ($scope === '*' || $name === $scope || str_starts_with($name, $scope . '\\')) {
                return true;
            }
        }

        return false;
    }
}
