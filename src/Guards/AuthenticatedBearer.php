<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;

/**
 * An access token the bearer path accepted: whom it admitted, and, for a token
 * a client credentials exchange issued, the API key it was exchanged for and
 * the scopes it grants.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthenticatedBearer
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  ?string  $credentialId
     * @param  ?list<string>  $scopes
     */
    public function __construct(

        /** The identity, principal, tenant and device the token admitted. */
        public Admitted $admitted,

        /** The API key a client credentials token was exchanged for, if it was. */
        #[\SensitiveParameter]
        public ?string $credentialId = null,

        /** The scopes a client credentials token grants, if it was one. */
        public ?array $scopes = null,
    ) {}

    /**
     * The method the request reports: `client_credentials` for a client
     * credentials token, otherwise the one the device's session records, if
     * any.
     *
     * @return ?string
     */
    public function method(): ?string
    {
        return $this->credentialId === null ? $this->admitted->device?->getSignInMethod() : ClientCredentialsExchange::METHOD;
    }
}
