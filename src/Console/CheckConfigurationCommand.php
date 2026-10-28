<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Command;
use Illuminate\Foundation\Application;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Codes\CodeKeys;
use SineMacula\Laravel\Authentication\Codes\CodeSettings;
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Database\DeviceRetention;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptLimits;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `authentication:check`: resolves every setting of each `jwt` guard the way
 * the guard would, and the device model, and exits non-zero on a problem, for
 * deploy pipelines and readiness probes.
 *
 * Every check runs, so one run lists every problem, each as `[<guard>]
 * <message>`: the token service (keys, active kid, algorithm, key lengths,
 * lifetimes, leeway, issuer and audience), the identity provider, a principal
 * resolver override, the package audience policy's settings, every flow's rate
 * limits, the password identifier and the refresh token transport. The
 * package-wide settings are reported as `[device]` (the device model and the
 * pruning retention), `[sign_in]` (the pending sign-in lifetime) and `[codes]`
 * (the one-time code settings and key, and a sender bound when a guard allows
 * one of the package's code sign-in methods, with a warning, not a problem,
 * when their delivery runs on a `sync` queue connection). The command reads
 * configuration only: it opens no database connection and prints no secret.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'authentication:check')]
final class CheckConfigurationCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = 'authentication:check {--guard=* : Check only these guards}';

    /** @var string The console command description. */
    protected $description = 'Check the configuration of every jwt guard and the device model';

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
            $this->line('No jwt guards are configured.');
        }

        $problems = [];

        foreach ($this->packageChecks($config) as $subject => $checks) {

            $found = self::prefixed($subject, array_map(static fn (\Closure $check): ?string => self::problem($check), $checks));

            if ($found === []) {
                $this->info("[{$subject}] OK");
            }

            $problems = [...$problems, ...$found];
        }

        $this->warnAboutSynchronousCodeDelivery($config);

        foreach ($guards as $guard) {
            $problems = [...$problems, ...self::prefixed($guard, $this->guardProblems($guard, $config))];
        }

        foreach ($problems as $problem) {
            $this->error($problem);
        }

        return $problems === [] ? self::SUCCESS : self::FAILURE;
    }

    /**
     * The package-wide checks, by what they check: the device model and how
     * long pruning keeps a device, and the lifetime of a pending sign-in (a
     * further factor or a principal choice), each of which otherwise fails only
     * when it is first used.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return array<string, list<\Closure(): mixed>>
     */
    private function packageChecks(ConfigRepository $config): array
    {
        return [
            'device' => [
                static function () use ($config): void {
                    InvalidDeviceModelConfigurationException::validate($config->string('authentication.device.model', ''));
                },
                static fn (): int => DeviceRetention::days(),
            ],
            'sign_in' => [
                static fn (): int => (new PendingSignIns($config))->ttlSeconds(),
            ],
            'codes' => $this->codeChecks($config),
        ];
    }

    /**
     * The checks of the one-time code settings, each of which otherwise fails
     * only when a code is first issued: the numbers and the queue settings, the
     * key, and a sender bound when a guard allows a code sign-in method.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<\Closure(): mixed>
     */
    private function codeChecks(ConfigRepository $config): array
    {
        $guards = $this->codeGuards($config);
        $bound  = $this->laravel->bound(OneTimeCodeSender::class);

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
        ];
    }

    /**
     * Warn, without failing, when a guard allows a code sign-in method and the
     * codes are delivered on a `sync` queue connection: delivery then runs in
     * the web process after each response, where a worker is the production
     * setting. Malformed queue settings are left to the `[codes]` checks.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    private function warnAboutSynchronousCodeDelivery(ConfigRepository $config): void
    {
        try {
            $synchronous = (new CodeSettings($config))->deliversSynchronously();
        } catch (\InvalidArgumentException) {
            return;
        }

        if (!$synchronous || $this->codeGuards($config) === []) {
            return;
        }

        $this->warn('[codes] One-time codes are delivered on a `sync` queue connection, after each response in the web process; '
            . 'set `authentication.codes.queue.connection` to a worker-backed connection in production.');
    }

    /**
     * The `jwt` guards whose audience allows one of the package's code sign-in
     * methods.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return list<string>
     */
    private function codeGuards(ConfigRepository $config): array
    {
        $policy = $this->laravel->make(AudiencePolicy::class);
        $guards = $config->get('auth.guards');
        $found  = [];

        foreach (is_array($guards) ? $guards : [] as $name => $guard) {

            $name = (string) $name;

            if (!is_array($guard) || ($guard['driver'] ?? null) !== 'jwt' || !self::allowsCodes($policy, $name)) {
                continue;
            }

            $found[] = $name;
        }

        return $found;
    }

    /**
     * Whether the guard's audience allows one of the package's code sign-in
     * methods; a malformed audience allows none here, since the guard's own
     * checks report it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $policy
     * @param  string  $guard
     * @return bool
     */
    private static function allowsCodes(AudiencePolicy $policy, string $guard): bool
    {
        try {
            return $policy->allowsMethod($guard, CodeSignIn::PHONE) || $policy->allowsMethod($guard, CodeSignIn::EMAIL);
        } catch (\InvalidArgumentException) {
            return false;
        }
    }

    /**
     * The guards to check: those named with `--guard`, otherwise every guard
     * that uses the `jwt` driver.
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

        $guards = $config->get('auth.guards');
        $jwt    = [];

        foreach (is_array($guards) ? $guards : [] as $name => $guard) {

            if (!is_array($guard) || ($guard['driver'] ?? null) !== 'jwt') {
                continue;
            }

            $jwt[] = (string) $name;
        }

        return $jwt;
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

        if (!is_array($guardConfig) || ($guardConfig['driver'] ?? null) !== 'jwt') {
            return [is_array($guardConfig) ? 'Not a jwt guard.' : 'Not configured.'];
        }

        $problems = array_map(self::problem(...), $this->checks($guard, $guardConfig, $config));

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
            static function () use ($app, $guard): void {
                self::validateAudience($app->make(AudiencePolicy::class), $guard);
            },
            static fn (): mixed => array_map(static fn (AttemptFlow $flow): array => (new AttemptLimits($config))->for($guard, $flow), AttemptFlow::cases()),
            static fn (): mixed => (new PasswordSignIn($config))->identifierType($guard),
            static fn (): mixed => RefreshTokenSettings::forGuard($guard, $config),
        ];
    }

    /**
     * The guard's provider, failing unless it is an `IdentityProvider`, as the
     * `jwt` driver needs.
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
     * Validate the guard's audience settings when the bound policy is the
     * package's; a policy of the application's own reads its own settings.
     *
     * @param  mixed  $policy
     * @param  string  $guard
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function validateAudience(mixed $policy, string $guard): void
    {
        if (!$policy instanceof GuardAudiencePolicy) {
            return;
        }

        $policy->validate($guard);
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
