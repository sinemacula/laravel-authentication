<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;

/**
 * Passkey factor gate contract.
 *
 * Asked by the passkey service, synchronously, inside the transaction that
 * registers or removes one of an identity's passkeys, before the passkey's row
 * is written or deleted, so a factor package can refuse the change or join it.
 * The transaction is on the storage connection (a savepoint in the caller's),
 * so a gate's own reads, writes and locks must use that connection too, taking
 * its identity's and factors' locks before the passkey row's. To refuse, throw:
 * the whole change rolls back, the gate's work with it, and the exception
 * reaches the caller; never catch it to commit.
 *
 * When the factor package enables passkeys as a factor, `registering()`
 * associates the new credential in the same change, confirmed by the
 * registration's own assertion (its observed properties), and answers the
 * association; it may complete a pending session's factor from there
 * (`satisfy()`), which commits or rolls back with the registration. `null`
 * leaves the credential a sign-in credential only. The package's default,
 * `NoPasskeyFactors`, associates nothing and refuses nothing: without a factor
 * package no passkey is a factor. A passkey's use and its bookkeeping (sign
 * count, backup state) are no change the identity makes, so they are not gated.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface PasskeyFactorGate
{
    /**
     * Before the passkey the identity registered on the application is stored:
     * associate it as a factor, answer `null` to leave it a sign-in credential,
     * or throw to refuse it. The binding is the one the registration's options
     * were asked for, if any.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  ?string  $name
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
     */
    public function registering(Identity $identity, string $application, RegisteredPasskey $passkey, ?ProofBinding $binding, ?string $name): ?PasskeyFactorAssociation;

    /**
     * Before the identity's passkey (its id, and its credential id as canonical
     * unpadded base64url) is removed from the application: throw to refuse the
     * removal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @return void
     */
    public function removing(Identity $identity, string $application, string $passkeyId, #[\SensitiveParameter] string $credentialId): void;
}
