<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;

/**
 * The default factor code counters: no factor package is bound, so no factor's
 * type is enabled, and every factor code is refused before it is sent or
 * checked (`type_not_enabled`). Fail closed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RefuseFactorCodes implements FactorCodeCounters
{
    /**
     * Refuse the code.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    #[\Override]
    public function admit(FactorCodeBinding $binding): FactorCodeAdmission
    {
        return FactorCodeAdmission::refused(FactorCodeRefusal::TYPE_NOT_ENABLED);
    }

    /**
     * Refuse the attempt's outcome.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    #[\Override]
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed): FactorCodeAdmission
    {
        return FactorCodeAdmission::refused(FactorCodeRefusal::TYPE_NOT_ENABLED);
    }
}
