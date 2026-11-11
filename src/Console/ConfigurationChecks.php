<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Authentication\Http\ClientText;

/**
 * The checks other packages add to `authentication:check`, in the order they
 * were registered.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ConfigurationChecks
{
    /** @var int The longest message or guard name shown, in characters. */
    private const int MAX_LENGTH = 1000;

    /** @var list<string> The checks' abstracts, in the order registered. */
    private array $checks = [];

    /**
     * Register the check resolved from `$check`, once.
     *
     * @param  string  $check
     * @return void
     */
    public function register(string $check): void
    {
        if (in_array($check, $this->checks, true)) {
            return;
        }

        $this->checks[] = $check;
    }

    /**
     * The checks' abstracts, in the order registered.
     *
     * @return list<string>
     */
    public function registered(): array
    {
        return $this->checks;
    }

    /**
     * Run every registered check for the guards and answer what they found,
     * cleaned and in a stable order.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  list<string>  $guards
     * @return list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     */
    public function findings(Container $container, array $guards): array
    {
        $ranks    = array_flip($guards);
        $findings = [];

        foreach ($this->checks as $check) {
            $found = $this->run($container, $check, $guards);

            usort($found, static fn (ConfigurationFinding $left, ConfigurationFinding $right): int => self::rank($left, $ranks) <=> self::rank($right, $ranks));

            $findings = [...$findings, ...$found];
        }

        return array_map(static fn (ConfigurationFinding $finding): ConfigurationFinding => self::cleaned($finding), $findings);
    }

    /**
     * What one check found, or the error that it could not be asked.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  string  $check
     * @param  list<string>  $guards
     * @return array<array-key, \SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     */
    private function run(Container $container, string $check, array $guards): array
    {
        try {
            return self::ask($container->make($check), $guards);
        } catch (\Throwable $throwable) {
            return [ConfigurationFinding::error(sprintf('The configuration check [%s] failed: %s.', $check, $throwable::class))];
        }
    }

    /**
     * Ask the resolved check for its findings, which must all be findings.
     *
     * @param  mixed  $check
     * @param  list<string>  $guards
     * @return array<array-key, \SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     *
     * @throws \LogicException
     */
    private static function ask(mixed $check, array $guards): array
    {
        if (!$check instanceof ConfigurationCheck) {
            throw new \LogicException('It is not a configuration check.');
        }

        return self::validated($check->findings($guards));
    }

    /**
     * The findings, once each is known to be one: PHP does not check the
     * elements of a returned array.
     *
     * @param  array<mixed>  $found
     * @return array<array-key, \SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     *
     * @throws \LogicException
     */
    private static function validated(array $found): array
    {
        $valid = array_filter($found, static fn (mixed $finding): bool => $finding instanceof ConfigurationFinding);

        if (count($valid) !== count($found)) {
            throw new \LogicException('It answered something other than findings.');
        }

        return $valid;
    }

    /**
     * Where the finding's guard sorts: package-wide first, then the checked
     * guards in the order checked, then any other.
     *
     * @param  \SineMacula\Laravel\Authentication\Console\ConfigurationFinding  $finding
     * @param  array<string, int>  $ranks
     * @return int
     */
    private static function rank(ConfigurationFinding $finding, array $ranks): int
    {
        return $finding->guard === null ? PHP_INT_MIN : ($ranks[$finding->guard] ?? count($ranks));
    }

    /**
     * The finding with control characters removed from its message and guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Console\ConfigurationFinding  $finding
     * @return \SineMacula\Laravel\Authentication\Console\ConfigurationFinding
     */
    private static function cleaned(ConfigurationFinding $finding): ConfigurationFinding
    {
        return new ConfigurationFinding(
            $finding->severity,
            ClientText::clean($finding->message, self::MAX_LENGTH) ?? '(no message)',
            $finding->guard === null ? null : ClientText::clean($finding->guard, self::MAX_LENGTH),
        );
    }
}
