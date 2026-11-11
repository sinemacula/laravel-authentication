<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Command;
use Illuminate\Foundation\Application;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeySettings;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Console\Enums\FindingSeverity;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Database\SessionRetention;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Delivery\DeliverySettings;
use SineMacula\Laravel\Authentication\Freshness\FreshnessSettings;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeSettings;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySignIn;
use SineMacula\Laravel\Authentication\Passkeys\RelyingParty;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptLimits;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\PendingState;
use SineMacula\Laravel\Authentication\Sessions\RevocationSettings;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * `authentication:check`: resolves each guard's settings and the package-wide
 * settings as the package would, and exits non-zero on a problem.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'authentication:check')]
final class CheckConfigurationCommand extends Command
{
    /** @var list<string> The guard drivers the command checks. */
    private const array DRIVERS = ['jwt', 'api_key'];

    /** @var string The name and signature of the console command. */
    protected $signature = 'authentication:check {--guard=* : Check only these guards}';

    /** @var string The console command description. */
    protected $description = 'Check the configuration of every jwt and api_key guard and the session model';

    /**
     * Check the configuration and report each problem, or that there is none.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return int
     */
    public function handle(ConfigRepository $config): int
    {
        $guards = $this->guards($config);

        if ($guards === []) {
            $this->line('No jwt or api_key guards are configured.');
        }

        $problems = [];

        foreach ($this->packageChecks($config, $guards) as $subject => $checks) {

            $found = self::prefixed($subject, array_map(static fn (\Closure $check): ?string => self::problem($check), $checks));

            if ($found === []) {
                $this->info("[{$subject}] OK");
            }

            $problems = [...$problems, ...$found];
        }

        $this->warnAboutSynchronousDelivery($config);

        $registered = $this->laravel->make(ConfigurationChecks::class)->findings($this->laravel, $guards);

        $warnings = [
            ...(new ApplicationChecks($this->laravel, $config))->warnings($guards),
            ...(new PasswordChecks($this->laravel, $config))->warnings($guards),
            ...self::reported($registered, FindingSeverity::WARNING),
        ];

        foreach ($warnings as $warning) {
            $this->warn($warning);
        }

        foreach ($guards as $guard) {
            $problems = [...$problems, ...self::prefixed($guard, $this->guardProblems($guard, $config))];
        }

        $problems = [...$problems, ...self::reported($registered, FindingSeverity::ERROR)];

        foreach ($problems as $problem) {
            $this->error($problem);
        }

        return $problems === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The package-wide checks, by what they check, each of which otherwise
     * fails only when it is first used.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  list<string>  $checked
     * @return array<string, list<\Closure(): mixed>>
     */
    private function packageChecks(ConfigRepository $config, array $checked): array
    {
        $session = JwtGuards::names($config) === [] ? [] : [
            'session' => [
                static function (): void {
                    SessionLookup::model();
                },
                static fn (): int => SessionRetention::days(),
                static fn (): int => PendingState::ttlSeconds($config),
                static fn (): string => PendingState::credentialField($config),
            ],
        ];

        return [
            'storage' => [
                static fn (): ?string => self::configuredConnection($config, StorageConnection::name()),
                static fn (): ?string => self::configuredConnection($config, StorageConnection::forRateLimits()),
            ],
            ...$session,
            'passwords' => (new PasswordChecks($this->laravel, $config))->settings(),
            'codes'     => $this->codeChecks($config, $checked),
            'delivery'  => [
                static function () use ($config): void {
                    (new DeliverySettings($config))->validate();
                },
            ],
            'passkeys' => [
                static fn (): int => (new PasskeyChallenges($config))->ttlSeconds(),
            ],
            'api_keys' => [
                static fn (): string => ApiKeySettings::prefix(),
                static fn (): int => ApiKeySettings::rotationOverlapSeconds(),
                static fn (): int => ApiKeySettings::lastUsedThrottleSeconds(),
                static fn (): int => ApiKeySettings::pruneAfterDays(),
            ],
            'identifier_changes' => self::identifierChangeChecks($config),
            'revocation'         => [
                static function () use ($config): void {
                    (new RevocationSettings($config))->validate();
                },
            ],
            'freshness' => [
                static function () use ($config): void {
                    (new FreshnessSettings($config))->validate();
                },
            ],
        ];
    }

    /**
     * The connection, once it is known to be configured in
     * `database.connections`; `null`, the default connection, always is.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  ?string  $connection
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function configuredConnection(ConfigRepository $config, ?string $connection): ?string
    {
        if ($connection !== null && !is_array($config->get("database.connections.{$connection}"))) {
            throw new \InvalidArgumentException("The connection [{$connection}] the package's tables are to live on is not configured in `database.connections`.");
        }

        return $connection;
    }

    /**
     * The checks of the identifier change settings.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     */
    private static function identifierChangeChecks(ConfigRepository $config): array
    {
        return [
            static function () use ($config): void {
                (new IdentifierChangeSettings($config))->validate();
            },
        ];
    }

    /**
     * The checks of the one-time code settings, their key and their sender.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  list<string>  $checked
     * @return list<\Closure(): mixed>
     */
    private function codeChecks(ConfigRepository $config, array $checked): array
    {
        [$guards, $unanswered] = $this->codeGuards($config, $checked);

        $bound = $this->laravel->bound(OneTimeCodeSender::class);

        return [
            static function () use ($config): void {
                (new CodeSettings($config))->validate();
            },
            static function () use ($config): void {
                (new CodeKeys($config))->validate();
            },
            static function () use ($guards, $bound): void {
                if ($guards !== [] && !$bound) {
                    $message = sprintf('Guards [%s] allow a code sign-in method, but no %s is bound to deliver the codes.', implode(', ', $guards), OneTimeCodeSender::class);

                    throw new \LogicException($message);
                }
            },
            ...array_map(static fn (string $message): \Closure => static function () use ($message): never {
                throw new \LogicException($message);
            }, $unanswered),
        ];
    }

    /**
     * Warn when a `jwt` guard is configured and deliveries run on a `sync`
     * queue connection, or a `failover` one that can fall back to it.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    private function warnAboutSynchronousDelivery(ConfigRepository $config): void
    {
        $settings = new DeliverySettings($config);

        try {
            $synchronous = $settings->deliversSynchronously();
            $fallsBack   = $settings->fallsBackToSync();
        } catch (\InvalidArgumentException) {
            return;
        }

        if ((!$synchronous && !$fallsBack) || JwtGuards::names($config) === []) {
            return;
        }

        $this->warn($synchronous
            ? '[delivery] One-time codes, password reset links and codes, and identifier change codes and notices are delivered on a `sync` '
                . 'queue connection, after each response in the web process; set `authentication.delivery.queue.connection` to a '
                . 'worker-backed connection in production.'
            : '[delivery] One-time codes, password reset links and codes, and identifier change codes and notices are delivered on a '
                . '`failover` queue connection that can fall back to `sync`; each delivery is pushed after the response, and runs in the '
                . 'web process when it falls back. Set `authentication.delivery.queue.connection` to a worker-backed connection that '
                . 'cannot in production.');
    }

    /**
     * The `jwt` guards whose application allows a code sign-in method, and a
     * problem for each unchecked guard whose policy throws when asked.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @param  list<string>  $checked
     * @return array{0: list<string>, 1: list<string>}
     */
    private function codeGuards(ConfigRepository $config, array $checked): array
    {
        $policy     = $this->laravel->make(ApplicationPolicy::class);
        $methods    = $this->codeMethods();
        $guards     = $config->get('auth.guards');
        $found      = [];
        $unanswered = [];

        foreach (is_array($guards) ? $guards : [] as $name => $guard) {

            $name = (string) $name;

            $answer = is_array($guard) && ($guard['driver'] ?? null) === 'jwt' ? self::allowsAnyOf($policy, $name, $methods) : false;

            if ($answer instanceof \Exception && !in_array($name, $checked, true)) {
                $unanswered[] = self::unanswered($name, $answer);
            }

            if ($answer !== true) {
                continue;
            }

            $found[] = $name;
        }

        return [$found, $unanswered];
    }

    /**
     * The problem of a guard whose application policy throws when asked whether
     * it allows a code sign-in method.
     *
     * @param  string  $guard
     * @param  \Exception  $exception
     * @return string
     */
    private static function unanswered(string $guard, \Exception $exception): string
    {
        return "Guard [{$guard}]'s application policy could not say whether it allows a code sign-in method: {$exception->getMessage()}";
    }

    /**
     * The names of the registered sign-in methods that sign in with one-time
     * codes; one that cannot be built is left out.
     *
     * @return array<int, string>
     */
    private function codeMethods(): array
    {
        $manager = $this->laravel->make(SignInMethodManager::class);

        return array_filter($manager->names(), static function (string $name) use ($manager): bool {
            try {
                return $manager->method($name) instanceof CodeSignIn;
            } catch (\Throwable) {
                return false;
            }
        });
    }

    /**
     * Whether the guard's application allows any of the methods, or the
     * exception its policy throws when asked, as over settings it cannot read.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  string  $guard
     * @param  array<int, string>  $methods
     * @return bool|\Exception
     */
    private static function allowsAnyOf(ApplicationPolicy $policy, string $guard, array $methods): bool|\Exception
    {
        try {
            foreach ($methods as $method) {
                if ($policy->allowsMethod($guard, $method)) {
                    return true;
                }
            }

            return false;
        } catch (\Exception $exception) {
            return $exception;
        }
    }

    /**
     * The guards to check: those named with `--guard`, otherwise every guard
     * that uses the `jwt` or the `api_key` driver.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<string>
     */
    private function guards(ConfigRepository $config): array
    {
        /** @var list<string> $named */
        $named = $this->option('guard');

        if ($named !== []) {
            return array_keys(array_flip($named));
        }

        $guards  = $config->get('auth.guards');
        $checked = [];

        foreach (is_array($guards) ? $guards : [] as $name => $guard) {

            if (!is_array($guard) || !in_array($guard['driver'] ?? null, self::DRIVERS, true)) {
                continue;
            }

            $checked[] = (string) $name;
        }

        return $checked;
    }

    /**
     * Run every check of the guard, reporting OK when none finds a problem, and
     * answer what each found, `null` for none.
     *
     * @param  string  $guard
     * @param  \Illuminate\Config\Repository  $config
     * @return list<?string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function guardProblems(string $guard, ConfigRepository $config): array
    {
        $guardConfig = $config->get("auth.guards.{$guard}");
        $driver      = is_array($guardConfig) ? ($guardConfig['driver'] ?? null) : null;

        if (!is_array($guardConfig) || !in_array($driver, self::DRIVERS, true)) {
            return [is_array($guardConfig) ? 'Not a jwt or api_key guard.' : 'Not configured.'];
        }

        $checks   = $driver === 'jwt' ? $this->checks($guard, $guardConfig, $config) : $this->apiKeyGuardChecks($guard, $guardConfig, $config);
        $problems = array_map(self::problem(...), $checks);

        if (array_filter($problems, is_string(...)) === []) {
            $this->info("[{$guard}] OK");
        }

        return $problems;
    }

    /**
     * The checks of a `jwt` guard, each resolving one part of its configuration
     * as the guard would.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $guardConfig
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function checks(string $guard, array $guardConfig, ConfigRepository $config): array
    {
        $app = $this->laravel;

        assert($app instanceof Application);

        $auth     = $app->make('auth');
        $provider = $guardConfig['provider'] ?? null;

        return [
            static fn (): mixed => (new JwtTokenServiceFactory($app, $config))->forGuard($guard),
            static fn (): mixed => self::identityProvider($guard, $auth->createUserProvider(is_string($provider) ? $provider : '')),
            static fn (): mixed => AuthenticationServiceProvider::resolveGuardPrincipalResolver($app, $guard, $guardConfig),
            static function () use ($app, $config, $guard): void {
                (new ApplicationChecks($app, $config))->validate($guard);
            },
            static fn (): mixed => array_map(static fn (AttemptFlow $flow): array => (new AttemptLimits($config))->for($guard, $flow), AttemptFlow::cases()),
            static fn (): mixed => (new PasswordSignIn($config))->identifierType($guard),
            static fn (): mixed => RefreshTokenSettings::forGuard($guard, $config),
            static function () use ($config, $guard): void {
                (new FreshnessSettings($config))->validate($guard);
            },
            self::passkeyCheck($app, $guard, $guardConfig, $config),
        ];
    }

    /**
     * The passkey check of a `jwt` guard: its relying party, when it sets a
     * `passkeys` block or its policy allows `passkey`.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @param  string  $guard
     * @param  array<array-key, mixed>  $guardConfig
     * @param  \Illuminate\Config\Repository  $config
     * @return \Closure(): void
     */
    private static function passkeyCheck(Application $app, string $guard, array $guardConfig, ConfigRepository $config): \Closure
    {
        return static function () use ($app, $guard, $guardConfig, $config): void {
            if (!array_key_exists('passkeys', $guardConfig) && !self::allowsPasskeys($app->make(ApplicationPolicy::class), $guard)) {
                return;
            }

            RelyingParty::forGuard($guard, $config);
        };
    }

    /**
     * Whether the application policy allows the guard the `passkey` method;
     * `false` when it throws instead of answering.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  string  $guard
     * @return bool
     */
    private static function allowsPasskeys(ApplicationPolicy $policy, string $guard): bool
    {
        try {
            return $policy->allowsMethod($guard, PasskeySignIn::NAME);
        } catch (\Exception) {
            return false;
        }
    }

    /**
     * The checks of an `api_key` guard, each resolving one part of its
     * configuration as the guard would.
     *
     * @param  string  $guard
     * @param  array<array-key, mixed>  $guardConfig
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function apiKeyGuardChecks(string $guard, array $guardConfig, ConfigRepository $config): array
    {
        $app = $this->laravel;

        assert($app instanceof Application);

        $auth     = $app->make('auth');
        $provider = $guardConfig['provider'] ?? null;

        return [
            static fn (): mixed => self::identityProvider($guard, $auth->createUserProvider(is_string($provider) ? $provider : '')),
            static fn (): mixed => AuthenticationServiceProvider::resolveGuardPrincipalResolver($app, $guard, $guardConfig),
            static function () use ($app, $config, $guard): void {
                (new ApplicationChecks($app, $config))->validateApiKey($guard);
            },
            static fn (): mixed => array_map(static fn (AttemptFlow $flow): array => (new AttemptLimits($config))->for($guard, $flow), AttemptFlow::cases()),
        ];
    }

    /**
     * The guard's provider, failing unless it is an `IdentityProvider`, as the
     * package's drivers need.
     *
     * @param  string  $guard
     * @param  mixed  $provider
     * @return \SineMacula\Laravel\Authentication\Contracts\IdentityProvider
     *
     * @throws \InvalidArgumentException
     */
    private static function identityProvider(string $guard, mixed $provider): IdentityProvider
    {
        if (!$provider instanceof IdentityProvider) {
            throw new \InvalidArgumentException(sprintf('Auth guard [%s] provider must resolve to [%s]; got [%s].', $guard, IdentityProvider::class, get_debug_type($provider)));
        }

        return $provider;
    }

    /**
     * The problem a check found, or `null` when it found none.
     *
     * @param  \Closure(): mixed  $check
     * @return ?string
     */
    private static function problem(\Closure $check): ?string
    {
        try {
            $check();
        } catch (\Exception $exception) {
            return $exception->getMessage();
        }

        return null;
    }

    /**
     * The problems found, each prefixed with what was checked; a check that
     * found none is left out.
     *
     * @param  string  $subject
     * @param  list<?string>  $problems
     * @return list<string>
     */
    private static function prefixed(string $subject, array $problems): array
    {
        $prefixed = [];

        foreach ($problems as $problem) {

            if ($problem === null) {
                continue;
            }

            $prefixed[] = "[{$subject}] {$problem}";
        }

        return $prefixed;
    }

    /**
     * The messages of the findings of the severity, each prefixed with its
     * guard and escaped so markup prints as text.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>  $findings
     * @param  \SineMacula\Laravel\Authentication\Console\Enums\FindingSeverity  $severity
     * @return list<string>
     */
    private static function reported(array $findings, FindingSeverity $severity): array
    {
        $reported = [];

        foreach ($findings as $finding) {

            if ($finding->severity !== $severity) {
                continue;
            }

            $reported[] = OutputFormatter::escape($finding->guard === null ? $finding->message : "[{$finding->guard}] {$finding->message}");
        }

        return $reported;
    }
}
