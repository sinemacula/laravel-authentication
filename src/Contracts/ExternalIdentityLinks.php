<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\External\ExternalLink;

/**
 * External identity link contract.
 *
 * Resolves a result an external identity provider verified to the identity it
 * is linked to: only through a link made through exactly that connection, for
 * exactly that issuer and subject, compared byte for byte, and never by email
 * or any other attribute the provider asserted, so a provider can never sign in
 * an identity it was not linked to. The package asks it when an adapter signs
 * in or reauthenticates with an external result, inside the caller's
 * transaction and before it takes any lock of its own: read the links on the
 * write connection, taking whatever locks they need there. An exception it
 * throws reaches the caller and rolls the sign-in back.
 *
 * Linking, and the links themselves, belong to whatever implements it. The
 * package's default, `NoExternalLinks`, links nothing, so no external result
 * signs anyone in until an application binds its own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface ExternalIdentityLinks
{
    /**
     * The link made through the connection for the issuer and subject, with the
     * identity it maps to, or `null` when there is none.
     *
     * @param  string  $connectionId
     * @param  string  $issuer
     * @param  string  $subject
     * @return ?\SineMacula\Laravel\Authentication\External\ExternalLink
     */
    public function find(string $connectionId, string $issuer, string $subject): ?ExternalLink;
}
