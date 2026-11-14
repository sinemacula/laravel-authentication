<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use SineMacula\Laravel\Authentication\Contracts\ExternalIdentityLinks;

/**
 * The package's default external identity links: none, so every external
 * sign-in fails as unlinked.
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
     * @param  ?string  $nameIdFormat
     * @return null
     */
    #[\Override]
    public function find(string $connectionId, string $issuer, string $subject, ?string $nameIdFormat): null
    {
        return null;
    }
}
