<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Console\Command;
use Illuminate\Foundation\Application;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptLimits;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
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
 * limits, the password identifier and the refresh token transport. The command
 * reads configuration only: it opens no database connection and prints no
 * secret.
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

        $problems = self::prefixed('device', [
            self::problem(static function () use ($config): void {
                InvalidDeviceModelConfigurationException::validate($config->string('authentication.device.model', ''));
            }),
        ]);

        if ($problems === []) {
            $this->info('[device] OK');
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
