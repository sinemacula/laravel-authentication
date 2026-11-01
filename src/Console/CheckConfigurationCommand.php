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
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Database\SessionRetention;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Delivery\DeliverySettings;
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
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `authentication:check`: resolves every setting of each `jwt` and `api_key`
 * guard the way the guard would, and the package-wide settings, and exits
 * non-zero on a problem, for deploy pipelines and readiness probes.
 *
 * Every check runs, so one run lists every problem, each as
 * `[<guard>] <message>`. For a `jwt` guard: the token service (keys, active
 * kid, algorithm, key lengths, lifetimes, leeway, and the issuer and audience,
 * which are required, so a guard with either unset reports it), the identity
 * provider, a principal resolver override, its application (the package
 * application policy's settings, or that a policy of the application's own
 * answers), every flow's rate limits, the password identifier, the refresh
 * token transport, and the passkey relying party when the guard's application
 * allows passkeys or the guard configures one. For an `api_key` guard: the
 * identity provider, a principal resolver override, its application (that it
 * allows `api_key`, and with the package's policy that its settings are valid),
 * and every flow's rate limits. The package-wide settings are reported as
 * `[storage]` (the storage connection and the rate limits connection, each a
 * connection name configured in `database.connections`, or none), `[session]`
 * (while a `jwt` guard is configured: the session model, which must live on the
 * storage connection, and the pruning retention), `[sign_in]` (the pending
 * sign-in lifetime), `[passwords]` (the password policy settings), `[codes]`
 * (the one-time code settings and key, a sender bound when a guard allows a
 * code sign-in method, the package's or an application's own `CodeSignIn`, and
 * an exception a guard's application policy throws when asked whether it allows
 * one, for a guard `--guard` leaves out; a checked guard reports it as its own
 * problem), `[delivery]` (the delivery queue, with a warning, not a problem,
 * when a `jwt` guard is configured and deliveries run on a `sync` queue
 * connection, or a `failover` one that can fall back to `sync`), `[passkeys]`
 * (the passkey challenge lifetime), `[api_keys]` (the key prefix, the rotation
 * overlaps, the last-use throttle and the pruning retention) and
 * `[identifier_changes]` (the pending change lifetime and the
 * recent-authentication window). It also warns about a `jwt` guard whose
 * package application settings allow no sign-in method or machine credential
 * (see `ApplicationChecks::warnings()`), and one whose password resets and
 * identifier changes would refuse to run (see `PasswordChecks::warnings()`).
 * The command reads configuration only: its own checks open no database
 * connection, though a policy of the application's own may open one when asked,
 * and it prints no secret.
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

        $warnings = [
            ...(new ApplicationChecks($this->laravel, $config))->warnings($guards),
            ...(new PasswordChecks($this->laravel, $config))->warnings($guards),
        ];

        foreach ($warnings as $warning) {
            $this->warn($warning);
        }

        foreach ($guards as $guard) {
            $problems = [...$problems, ...self::prefixed($guard, $this->guardProblems($guard, $config))];
        }

        foreach ($problems as $problem) {
            $this->error($problem);
        }

        return $problems === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The package-wide checks, by what they check: the connections the
     * package's tables live on, the session model and how long pruning keeps a
     * session (only while a `jwt` guard, which keeps sessions, is configured),
     * the lifetime of a pending sign-in (a further factor or a principal
     * choice), the API key settings and the identifier change settings, each of
     * which otherwise fails only when it is first used.
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
            ],
        ];

        return [
            'storage' => [
                static fn (): ?string => self::configuredConnection($config, StorageConnection::name()),
                static fn (): ?string => self::configuredConnection($config, StorageConnection::forRateLimits()),
            ],
            ...$session,
            'sign_in' => [
                static fn (): int => (new PendingSignIns($config))->ttlSeconds(),
            ],
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
     * The checks of the identifier change settings, each of which otherwise
     * fails only when a change is first requested or confirmed: the pending
     * change's lifetime and the recent-authentication window.
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
     * The checks of the one-time code settings, each of which otherwise fails
     * only when a code is first issued: the numbers, the key, a sender bound
     * when a guard allows a code sign-in method, and the exception a policy
     * throws when asked whether a guard `--guard` leaves out does.
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
     * Warn, without failing, when a `jwt` guard is configured and the package's
     * deliveries (one-time codes, password reset links and codes, identifier
     * change codes and notices) run on a `sync` queue connection, or on a
     * `failover` one that can fall back to `sync`: delivery then runs in the
     * web process after a response, where a worker is the production setting.
     * Malformed queue settings are left to the `[delivery]` check.
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
     * problem for each guard outside the checked ones whose application policy
     * throws when asked. A guard that is checked has its policy asked again by
     * its own application check, which reports what it throws, so it is left
     * out of both here.
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
     * codes: the package's `phone_code` and `email_code`, and any the
     * application registered as a `CodeSignIn` of its own. A method that cannot
     * be built, whatever its factory throws (an exception, or an error such as
     * a `TypeError`), is left to the sign-ins that use it.
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
     * Run every check of the guard, reporting it as checked when none finds a
     * problem: what each check found, `null` for none.
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
            self::passkeyCheck($app, $guard, $guardConfig, $config),
        ];
    }

    /**
     * The passkey check of a `jwt` guard: its relying party, resolved as its
     * passkeys would resolve it, when it sets a `passkeys` block or the bound
     * application policy allows it the `passkey` method. An exception the
     * policy throws when asked is reported by the application check alone.
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
}
