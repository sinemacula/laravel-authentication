<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Secrets\Secret;

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
 * (`satisfy()`), or judge an active current session again once the passkey
 * counts as a factor (`factorChanged()` with `PASSKEY_FACTOR_REGISTERED`), and
 * either commits or rolls back with the registration. `null` leaves the
 * credential a sign-in credential only. When a passkey factor is removed,
 * `removing()` carries out the factor package's own removal (`factorRemoved()`
 * for the factor, which judges the current session again). Each may answer the
 * factor package's completion of the change, which the passkey service's caller
 * gets back uninterpreted. Both are handed the client of the request they act
 * for, the one the registration or removal was given, as a plain value, to
 * judge, report and record with; a gate never reads the guard's request for it.
 * The package's default, `NoPasskeyFactors`, associates nothing, completes
 * nothing and refuses nothing: without a factor package no passkey is a factor.
 * A passkey's use and its bookkeeping (sign count, backup state) are no change
 * the identity makes, so they are not gated.
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
     * were asked for, if any. The association's completion reaches the
     * registration's caller as `PasskeyRegistration::$factor->completion`; a
     * duplicate credential found by the insert rolls back everything the gate
     * did and answers no association.
     *
     * The pending credential is what the registration's caller handed in as the
     * credential of a pending sign-in the passkey enrols a factor for (a
     * bootstrap enrolment), as a `Secret`; `null` for an ordinary registration.
     * Before the gate is asked, the package has proved, in this transaction,
     * under the lock of the identity's row and then of the session's, that it
     * names a live pending session of this identity on this guard and, when the
     * challenge was bound, the session it was bound to; so the gate completes
     * the session's factor by handing the credential and the client to
     * `SessionService::satisfy()` itself, with the proof the registration
     * confirmed. A refusal from `satisfy()` is answered, not thrown, and the
     * session's factor may legitimately stay outstanding (another factor is
     * still owed): a gate that requires the completion must check the result
     * and throw to roll back the whole registration, the association with it.
     * `satisfy()` reports its own refusal; the gate reports nothing more.
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
     * Before the identity's passkey (its id, and its credential id as canonical
     * unpadded base64url) is removed from the application: throw to refuse the
     * removal, or answer the factor package's completion of it, `null` for
     * none, which reaches the removal's caller as `PasskeyRemoval::$completion`
     * once the passkey is removed; a passkey removed concurrently rolls back
     * everything the gate did and answers no completion. The client is the one
     * the removal was given.
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
