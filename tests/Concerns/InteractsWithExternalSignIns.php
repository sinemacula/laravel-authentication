<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Fixtures\External\FakeExternalLinks;

/**
 * Shared set-up for tests that sign in with results an external identity
 * provider verified: a fake link contract bound in the container, links made on
 * it, and results through those links.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithExternalSignIns
{
    /** @var string The issuer every result in these tests asserts. */
    protected const string ISSUER = 'https://idp.example.test';

    /**
     * The fake link contract, bound in the container the first time it is asked
     * for.
     *
     * @return \Tests\Fixtures\External\FakeExternalLinks
     */
    protected function externalLinks(): FakeExternalLinks
    {
        $links = app(ExternalIdentityLinks::class);

        if ($links instanceof FakeExternalLinks) {
            return $links;
        }

        $links = new FakeExternalLinks;

        app()->instance(ExternalIdentityLinks::class, $links);

        return $links;
    }

    /**
     * A sign-in context from no particular client that names the principal to
     * act as.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    protected static function asPrincipal(Principal $principal): SignInContext
    {
        return new SignInContext(new ClientContext(null, null), principal: $principal);
    }

    /**
     * Link the identity through the connection, its subject the identity's own
     * key unless one is given, and answer a result through that link.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $linkId
     * @param  ?string  $subject
     * @param  ?string  $tenantId
     * @param  ?\Carbon\CarbonInterface  $authenticatedAt
     * @param  ?\Carbon\CarbonInterface  $sessionNotAfter
     * @param  ?string  $policyVersion
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @return \SineMacula\Laravel\Authentication\External\ExternalResult
     */
    protected function linkedResult(
        Identity $identity,
        string $connectionId = 'connection-7',
        string $linkId = 'link-1',
        ?string $subject = null,
        ?string $tenantId = null,
        ?CarbonInterface $authenticatedAt = null,
        ?CarbonInterface $sessionNotAfter = null,
        ?string $policyVersion = null,
        ?ExternalEvidence $evidence = null,
    ): ExternalResult {
        $subject ??= 'subject-' . IdentifierCoercion::stringify($identity->getAuthIdentifier());

        $this->externalLinks()->link($identity, $linkId, $connectionId, self::ISSUER, $subject);

        return new ExternalResult($connectionId, self::ISSUER, $subject, $tenantId, $authenticatedAt, $sessionNotAfter, $policyVersion, $evidence);
    }
}
