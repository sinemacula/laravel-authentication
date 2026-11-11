<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * A check another package adds to `authentication:check`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ConfigurationCheck
{
    /**
     * The findings about the guards being checked and the package-wide settings
     * the check owns.
     *
     * @param  list<string>  $guards
     * @return list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     */
    public function findings(array $guards): array;
}
