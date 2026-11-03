<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passkeys;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;

/**
 * The package's default passkey factor gate: no passkey is a factor, so there
 * is nothing to gate. Every passkey registered is a sign-in credential only,
 * and every removal goes ahead. Bind a factor package's gate to change that.
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
     * @return null
     */
    #[\Override]
    public function registering(Identity $identity, string $application, RegisteredPasskey $passkey, ?ProofBinding $binding, ?string $name): null
    {
        return null;
    }

    /**
     * Let the removal go ahead.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @return void
     */
    #[\Override]
    public function removing(Identity $identity, string $application, string $passkeyId, #[\SensitiveParameter] string $credentialId): void {}
}
