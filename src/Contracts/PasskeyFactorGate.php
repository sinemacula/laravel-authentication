<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Lets a factor package refuse or join the registration or removal of a
 * passkey, inside the transaction that makes it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PasskeyFactorGate
{
    /**
     * Before the passkey is stored: associate it as a factor, answer `null` to
     * leave it a sign-in credential, or throw to refuse it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  ?string  $name
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $pending
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
     */
    public function registering(
        Identity $identity,
        string $application,
        RegisteredPasskey $passkey,
        ?ProofBinding $binding,
        ?string $name,
        ClientContext $client,
        #[\SensitiveParameter] ?Secret $pending,
    ): ?PasskeyFactorAssociation;

    /**
     * Before the identity's passkey is removed: throw to refuse the removal, or
     * answer the factor package's completion of it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?object
     */
    public function removing(Identity $identity, string $application, string $passkeyId, #[\SensitiveParameter] string $credentialId, ClientContext $client): ?object;
}
