<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * A factor policy that asks for the requirement it was given (none unless one
 * is) and, the first time it is asked, runs the change it was given: a stand-in
 * for a deactivation or deletion that commits while a sign-in or a choice, past
 * its admission, has not yet written its session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class InterruptingFactorPolicy implements AdditionalFactorPolicy
{
    /** @var bool Whether the change has run. */
    public bool $interrupted = false;

    /**
     * Constructor.
     *
     * @param  \Closure(): mixed  $change
     * @param  \SineMacula\Laravel\Authentication\Requirements\Requirement  $requirement
     */
    public function __construct(

        /** The change to run the first time the policy is asked. */
        private readonly \Closure $change,

        /** The requirement it answers with. */
        private readonly Requirement $requirement = new Requirement,
    ) {}

    /**
     * Run the change the first time, and ask for the requirement.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(AdditionalFactorContext $context): Requirement
    {
        if (!$this->interrupted) {

            $this->interrupted = true;

            ($this->change)();
        }

        return $this->requirement;
    }
}
