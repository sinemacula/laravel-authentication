<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Configuration check contract.
 *
 * A check another package adds to `authentication:check`, registered with
 * `ConfigurationChecks::register()`. The command asks each registered check,
 * after its own, for its findings about the guards being checked (those named
 * with `--guard`, otherwise every `jwt` and `api_key` guard), and prints them
 * like its own: an error finding fails the command, a warning does not.
 *
 * A check reads configuration and bindings only. It never opens a connection or
 * makes a call that has a side effect (a network request, a write, a delivery),
 * as the command runs in deploy pipelines and readiness probes. Its findings
 * name settings, never their values: the output is shown in logs, so a finding
 * must not carry a key, a secret, a credential or an identifier.
 *
 * A check is resolved from the container each time the command runs. One that
 * throws, or that answers anything but findings, is reported as an error
 * finding naming its class, and the checks after it still run. Return the
 * findings in an order of your own: they are shown in the order checks were
 * registered, then guards (package-wide first), then that order.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ConfigurationCheck
{
    /**
     * The findings about the guards being checked, and about the package-wide
     * settings the check owns (a finding with no guard); none when there is
     * nothing to report.
     *
     * @param  list<string>  $guards
     * @return list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     */
    public function findings(array $guards): array;
}
