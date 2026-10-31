<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

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
 * docblock. Names resolve as PHP resolves them, without regard to case, and a
 * qualified name only through a class or namespace import. The source is
 * tokenised, not parsed, so a name built at run time (a class name in a string,
 * say) and an unqualified name of a class in the same namespace are not seen:
 * the test is a backstop for the rules, not a proof of them.
 *
 * One rule is about calls rather than names: only the guards call the rebind
 * methods of a `GuardContext`, so each context has one rebind path, its guard.
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
    private const string DOCBLOCK_NAME = '/\\\(SineMacula\\\Laravel\\\Authentication\\\[A-Za-z0-9_\\\]+)/i';

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
        'admission, devices and the support helpers name nothing of tokens, sessions or guards' => [
            'from'    => ['Admission', 'Devices', 'Support'],
            'except'  => [],
            'forbids' => ['Jwt', 'Sessions', 'Guards'],
            'allows'  => [],
        ],
        'the guard context names nothing of guards, sessions or tokens' => [
            'from'    => ['Runtime'],
            'except'  => [],
            'forbids' => ['Guards', 'Sessions', 'Jwt'],
            'allows'  => [],
        ],
        'the session revocations and the password writer name no guard' => [
            'from'    => ['Sessions\SessionRevocations', 'Passwords\PasswordWriter'],
            'except'  => [],
            'forbids' => ['Guards'],
            'allows'  => [],
        ],
        'tokens, API keys and client credentials name nothing of sessions but the sign-in request' => [
            'from'    => ['Jwt', 'ApiKeys', 'ClientCredentials'],
            'except'  => [],
            'forbids' => ['Sessions'],
            'allows'  => ['Sessions\SignInRequest'],
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

    /** @var ?array<string, string> Every class of the package and its source, read once. */
    private static ?array $sources = null;

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
        self::assertSame([], self::violations(self::names(), $from, $except, $forbids, $allows));
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
     * Only the guards rebind a guard's context: no class outside `Guards` calls
     * one of `GuardContext`'s `rebind*()` methods, so the guard that owns a
     * context is its one rebind path.
     *
     * @return void
     */
    public function testOnlyTheGuardsRebindAGuardContext(): void
    {
        $calls = [];

        foreach (self::sources() as $class => $source) {

            if (self::isWithin($class, ['Guards'])) {
                continue;
            }

            foreach (self::rebindsIn($source) as $method) {
                $calls[] = "{$class} calls {$method}()";
            }
        }

        self::assertSame([], $calls);
    }

    /**
     * The scanner finds a call of each of the context's rebind methods, through
     * `->` or `?->` and in any case, and nothing for a declaration, a function
     * call, or a method of another name that starts the same way.
     *
     * @return void
     */
    public function testTheScannerFindsEveryCallOfAContextRebind(): void
    {
        $source = <<<'PHP'
            <?php

            final class Example
            {
                public function rebindRequest(): void {}

                public function run(): void
                {
                    $this->context->rebindRequest($request);
                    $context?->rebindEvents($events);
                    $this->context->REBINDRESOLVER($resolver);
                    $app->rebinding('request', $callback);
                    $this->rebindFrom($manager);
                    rebindRequest();
                }
            }
            PHP;

        self::assertSame(['rebindRequest', 'rebindEvents', 'rebindResolver'], self::rebindsIn($source));
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
     * A qualified name resolves through the class or namespace import its first
     * segment names, whatever its case, and not through a function's or a
     * constant's import of the same name, alone or within a group; a rule
     * catches a forbidden name whatever its case, fully qualified in code or in
     * a docblock.
     *
     * @return void
     */
    public function testTheScannerResolvesAQualifiedNameAsPhpDoes(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Authentication\Models;

            use SineMacula\Laravel\Authentication as Auth;
            use SineMacula\Laravel\Authentication\Guards as Guarding;
            use SineMacula\Laravel\Authentication\Jwt as Tokens;
            use function Other\Auth;
            use CONST Other\Guarding;
            use Other\{FUNCTION tokenise as Tokens, const Auth};

            /**
             * @see \sinemacula\laravel\authentication\sessions\SessionService
             */
            final class Example
            {
                public function run(): void
                {
                    new Auth\Jwt\TokenLifetimes;
                    new auth\Sessions\DeviceProof;
                    new GUARDING\JwtGuard;
                    new tokens\JwtKeyring;
                    new \sinemacula\laravel\authentication\jwt\MachineTokens;
                }
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Guards',
            'Guards\JwtGuard',
            'Jwt',
            'Jwt\JwtKeyring',
            'Jwt\TokenLifetimes',
            'Sessions\DeviceProof',
            'jwt\MachineTokens',
            'sessions\SessionService',
        ], $names);

        self::assertSame([
            'Models\Example names Guards',
            'Models\Example names Guards\JwtGuard',
            'Models\Example names Jwt',
            'Models\Example names Jwt\JwtKeyring',
            'Models\Example names Jwt\TokenLifetimes',
            'Models\Example names Sessions\DeviceProof',
            'Models\Example names jwt\MachineTokens',
            'Models\Example names sessions\SessionService',
        ], self::violations(['Models\Example' => $names], ['models'], [], ['JWT', 'Sessions', 'Guards'], []));
    }

    /**
     * What each class a rule applies to names that the rule forbids.
     *
     * @param  array<string, list<string>>  $classes
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return list<string>
     */
    private static function violations(array $classes, array $from, array $except, array $forbids, array $allows): array
    {
        $violations = [];

        foreach ($classes as $class => $names) {

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

        return $violations;
    }

    /**
     * Every class of the package and the package names it names, relative to
     * the package, read once.
     *
     * @return array<string, list<string>>
     */
    private static function names(): array
    {
        return self::$names ??= array_map(self::namesIn(...), self::sources());
    }

    /**
     * Every class of the package and its source, by its name relative to the
     * package, read once.
     *
     * @return array<string, string>
     */
    private static function sources(): array
    {
        if (self::$sources !== null) {
            return self::$sources;
        }

        $source  = dirname(__DIR__, 3) . '/src/';
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));
        $sources = [];

        foreach ($files as $file) {

            assert($file instanceof \SplFileInfo);

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $class = str_replace('/', '\\', substr($file->getPathname(), strlen($source), -4));

            $sources[$class] = (string) file_get_contents($file->getPathname());
        }

        ksort($sources);

        return self::$sources = $sources;
    }

    /**
     * The context rebind methods the source calls, in order, each as
     * `GuardContext` declares it.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function rebindsIn(string $source): array
    {
        $rebinds = self::contextRebinds();
        $tokens  = self::tokens($source);
        $calls   = [];

        foreach ($tokens as $index => $token) {

            $method = $tokens[$index + 1] ?? null;

            if (!self::isCallOperator($token) || !is_array($method) || $method[0] !== T_STRING || ($tokens[$index + 2] ?? null) !== '(') {
                continue;
            }

            $calls[] = $rebinds[strtolower($method[1])] ?? null;
        }

        return array_values(array_filter($calls, static fn (?string $call): bool => $call !== null));
    }

    /**
     * The rebind methods `GuardContext` declares, by their lower-cased names.
     *
     * @return array<string, string>
     */
    private static function contextRebinds(): array
    {
        $methods = array_map(static fn (\ReflectionMethod $method): string => $method->getName(), (new \ReflectionClass(GuardContext::class))->getMethods());
        $rebinds = array_filter($methods, static fn (string $method): bool => str_starts_with($method, 'rebind'));

        return array_combine(array_map(strtolower(...), $rebinds), $rebinds);
    }

    /**
     * Whether the token is an object operator, `->` or `?->`.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @return bool
     */
    private static function isCallOperator(array|string $token): bool
    {
        return is_array($token) && in_array($token[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true);
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

        $package = array_filter($names, static fn (?string $name): bool => $name !== null && strncasecmp($name, self::PACKAGE, strlen(self::PACKAGE)) === 0);

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
     * The names an import statement imports, recording the alias each class or
     * namespace import gives by its lower case. A qualified name resolves only
     * through those, without regard to case: a function's or a constant's
     * import of the same name is kept apart from them.
     *
     * @param  string  $statement
     * @param  array<string, string>  $aliases
     * @return list<string>
     */
    private static function imports(string $statement, array &$aliases): array
    {
        [$kind, $statement] = self::kind($statement, '');

        $prefix = '';

        if (preg_match('/^(.*)\\\\\{(.*)\}$/', $statement, $group) === 1) {
            [, $prefix, $statement] = $group;

            $prefix .= '\\';
        }

        $names = [];

        foreach (explode(',', $statement) as $import) {

            [$member, $import] = self::kind($import, $kind);

            $parts = explode(' as ', $import);
            $name  = ltrim($prefix . $parts[0], '\\');
            $alias = $parts[1] ?? substr((string) strrchr('\\' . $name, '\\'), 1);

            if ($member === '') {
                $aliases[strtolower($alias)] = $name;
            }

            $names[] = $name;
        }

        return $names;
    }

    /**
     * What the import imports, `function`, `const` or `''` for a class or a
     * namespace, and the import without the word that gives it: a whole
     * statement's, or one member's of a group, which imports what its statement
     * does unless it gives its own.
     *
     * @param  string  $import
     * @param  string  $kind
     * @return array{0: string, 1: string}
     */
    private static function kind(string $import, string $kind): array
    {
        if (preg_match('/^(function|const) (.*)$/i', $import, $match) === 1) {
            return [strtolower($match[1]), $match[2]];
        }

        return [$kind, $import];
    }

    /**
     * The fully qualified name a name token stands for: a qualified name
     * through the alias its first segment names, whatever its case, or else
     * relative to the namespace; `null` for any other token.
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

        $alias = strtolower($first);

        return isset($aliases[$alias]) ? $aliases[$alias] . '\\' . $rest : ltrim($namespace . '\\' . $text, '\\');
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
     * them, without regard to case; `*` stands for the whole package.
     *
     * @param  string  $name
     * @param  list<string>  $scopes
     * @return bool
     */
    private static function isWithin(string $name, array $scopes): bool
    {
        $name = strtolower($name);

        foreach (array_map(strtolower(...), $scopes) as $scope) {
            if ($scope === '*' || $name === $scope || str_starts_with($name, $scope . '\\')) {
                return true;
            }
        }

        return false;
    }
}
