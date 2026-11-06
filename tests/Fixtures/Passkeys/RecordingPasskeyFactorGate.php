<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passkeys;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PasskeyFactorGate;
use SineMacula\Laravel\Authentication\Database\StorageConnection;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Passkey factor gate a factor package's adapter might bind: it keeps what it
 * was asked and answers as the test scripts it (by default associating every
 * passkey as factor `factor-<passkey id>` and letting every removal go ahead,
 * completing nothing), and, as the factor package requires, refuses to run
 * outside a transaction on the storage connection.
 *
 * @phpstan-type Registration array{
 *     identity: \SineMacula\Laravel\Authentication\Contracts\Identity,
 *     application: string,
 *     passkey: \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey,
 *     binding: ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding,
 *     name: ?string,
 *     client: \SineMacula\Laravel\Authentication\Http\ClientContext,
 *     pending: ?\SineMacula\Laravel\Authentication\Secrets\Secret,
 * }
 * @phpstan-type Scripted \Closure(
 *     \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey,
 *     ?\SineMacula\Laravel\Authentication\Secrets\Secret,
 *     \SineMacula\Laravel\Authentication\Http\ClientContext,
 * ): ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
 * @phpstan-type Removal array{
 *     identity: \SineMacula\Laravel\Authentication\Contracts\Identity,
 *     application: string,
 *     passkeyId: string,
 *     credentialId: string,
 *     client: \SineMacula\Laravel\Authentication\Http\ClientContext,
 * }
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingPasskeyFactorGate implements PasskeyFactorGate
{
    /** @var list<Registration> Every registration it was asked about, in order. */
    public array $registrations = [];

    /** @var list<Removal> Every removal it was asked about, in order. */
    public array $removals = [];

    /**
     * Constructor.
     *
     * @param  ?Scripted  $onRegistering
     * @param  ?\Closure(string, string): ?object  $onRemoving
     */
    public function __construct(

        /** Answers a registration in place of the default association. */
        private readonly ?\Closure $onRegistering = null,

        /** Runs on a removal, before it goes ahead, and answers its completion. */
        private readonly ?\Closure $onRemoving = null,
    ) {}

    /**
     * Keep the registration and answer it as scripted.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  \SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey  $passkey
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\ProofBinding  $binding
     * @param  ?string  $name
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $pending
     * @return ?\SineMacula\Laravel\Authentication\Passkeys\PasskeyFactorAssociation
     *
     * @throws \LogicException
     */
    #[\Override]
    public function registering(
        Identity $identity,
        string $application,
        RegisteredPasskey $passkey,
        ?ProofBinding $binding,
        ?string $name,
        ClientContext $client,
        ?Secret $pending,
    ): ?PasskeyFactorAssociation {
        self::assertInsideTheStorageTransaction();

        $this->registrations[] = [
            'identity'    => $identity,
            'application' => $application,
            'passkey'     => $passkey,
            'binding'     => $binding,
            'name'        => $name,
            'client'      => $client,
            'pending'     => $pending,
        ];

        return $this->onRegistering === null ? new PasskeyFactorAssociation('factor-' . $passkey->id) : ($this->onRegistering)($passkey, $pending, $client);
    }

    /**
     * Keep the removal, run the scripted step and answer its completion.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  string  $passkeyId
     * @param  string  $credentialId
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?object
     *
     * @throws \LogicException
     */
    #[\Override]
    public function removing(Identity $identity, string $application, string $passkeyId, string $credentialId, ClientContext $client): ?object
    {
        self::assertInsideTheStorageTransaction();

        $this->removals[] = ['identity' => $identity, 'application' => $application, 'passkeyId' => $passkeyId, 'credentialId' => $credentialId, 'client' => $client];

        return $this->onRemoving === null ? null : ($this->onRemoving)($passkeyId, $credentialId);
    }

    /**
     * Refuse to run outside a transaction on the storage connection, as the
     * factor package does.
     *
     * @return void
     *
     * @throws \LogicException
     */
    private static function assertInsideTheStorageTransaction(): void
    {
        if (DB::connection(StorageConnection::name())->transactionLevel() < 1) {
            throw new \LogicException('The passkey factor gate runs inside the storage connection\'s transaction.');
        }
    }
}
