<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;

/**
 * The package's default external identity links: none, so no external result
 * maps to an identity and every external sign-in fails as unlinked. Bind an
 * implementation of `ExternalIdentityLinks` to change that.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoExternalLinks implements ExternalIdentityLinks
{
    /**
     * Find no link.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return null
     */
    #[\Override]
    public function find(string $connectionId, string $issuer, string $subject): null
    {
        return null;
    }
}
