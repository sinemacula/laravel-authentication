<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use SineMacula\Laravel\Authentication\Codes\Enums\FactorCodeRefusal;
use SineMacula\Laravel\Authentication\Contracts\FactorCodeCounters;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * The default factor code counters, which refuse every factor code as
 * `type_not_enabled`.
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
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    #[\Override]
    public function admit(FactorCodeBinding $binding, ClientContext $client): FactorCodeAdmission
    {
        return FactorCodeAdmission::refused(FactorCodeRefusal::TYPE_NOT_ENABLED);
    }

    /**
     * Refuse the attempt's outcome.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\FactorCodeBinding  $binding
     * @param  string  $challengeId
     * @param  bool  $passed
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\FactorCodeAdmission
     */
    #[\Override]
    public function report(FactorCodeBinding $binding, string $challengeId, bool $passed, ClientContext $client): FactorCodeAdmission
    {
        return FactorCodeAdmission::refused(FactorCodeRefusal::TYPE_NOT_ENABLED);
    }
}
