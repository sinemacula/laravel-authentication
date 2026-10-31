<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\ApiKey;

/**
 * What presenting a key came to: the key its public part named, if any, and
 * either the owner admitted as the key's principal or the refusal with the
 * context established by then.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApiKeyOutcome
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Models\ApiKey  $key
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted|\SineMacula\Laravel\Authentication\Admission\Refused  $admission
     */
    public function __construct(

        /** The key the presented public part named, if one did. */
        public ?ApiKey $key,

        /** The admitted owner and principal, or why not. */
        public Admitted|Refused $admission,
    ) {}

    /**
     * The failure event of a refused key, for the flow and the client, with the
     * context the refusal established and, once a key was found, its id and
     * scopes. Never the key or its secret.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $identifier
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     */
    public function failure(
        Refused $refused,
        string $guard,
        AuthenticationFlow $flow,
        string $method,
        ClientContext $client,
        ?string $identifier = null,
        ?int $retryAfter = null,
    ): AuthenticationFailed {
        $context = new EventContext(
            $guard,
            $client,
            $refused->identity,
            $refused->principal,
            $refused->tenant,
            method: $method,
            credentialId: $this->key?->id,
            scopes: $this->key?->scopes,
        );

        return new AuthenticationFailed($context, $flow, $refused->reason, $identifier, $retryAfter);
    }
}
