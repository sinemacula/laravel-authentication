<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission;
use SineMacula\Laravel\Authentication\Codes\FactorCodeBinding;

/**
 * The factor package's per-factor and per-identity counts and lockouts for
 * factor codes.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface FactorCodeCounters
{
    /**
     * Whether a code for the binding may be sent or checked now.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    public function admit(FactorCodeBinding $binding): FactorCodeAdmission;

    /**
     * Count one attempt at the challenge's code and answer whether its outcome
     * stands.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed): FactorCodeAdmission;
}
