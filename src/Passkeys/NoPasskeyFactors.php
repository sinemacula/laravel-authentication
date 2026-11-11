<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * The default passkey factor gate, under which no passkey is a factor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NoPasskeyFactors implements PasskeyFactorGate
{
    /**
     * Associate nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  ?string  $name
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $pending
     * @return null
     */
    #[\Override]
    public function registering(
        Identity $identity,
        string $application,
        RegisteredPasskey $passkey,
        ?ProofBinding $binding,
        ?string $name,
        ClientContext $client,
        #[\SensitiveParameter] ?Secret $pending,
    ): null {
        return null;
    }

    /**
     * Let the removal go ahead, completing nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return null
     */
    #[\Override]
    public function removing(Identity $identity, string $application, string $passkeyId, #[\SensitiveParameter] string $credentialId, ClientContext $client): null
    {
        return null;
    }
}
