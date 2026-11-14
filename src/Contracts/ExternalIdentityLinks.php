<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\External\ExternalLink;

/**
 * Resolves a result an external identity provider verified to the identity it
 * is linked to, only through a link made through that connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ExternalIdentityLinks
{
    /**
     * The link made through the connection for the issuer and subject, and the
     * subject's SAML `NameID` format when it has one, with the identity it maps
     * to, or `null` when there is none.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @param  ?string  $nameIdFormat
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     */
    public function find(string $connectionId, string $issuer, string $subject, ?string $nameIdFormat): ?ExternalLink;
}
