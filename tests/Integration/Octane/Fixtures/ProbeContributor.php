<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;

/**
 * A contributor depending on a scoped service: it contributes the request id
 * its `RequestProbe` was resolved for, and the application the context is for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProbeContributor implements AuthenticationContextContributor
{
    /**
     * Constructor.
     *
     * @param  \Tests\Integration\Octane\Fixtures\RequestProbe  $probe
     */
    public function __construct(

        /** The scoped probe of the request being served. */
        private RequestProbe $probe,
    ) {}

    /**
     * The probe's request id and the context's application.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, mixed>
     */
    #[\Override]
    public function contribute(ContributionSubject $subject): array
    {
        return ['request_id' => $this->probe->requestId, 'application' => $subject->context->application];
    }
}
