<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Fixtures\Database\ShippedMigrations;

/**
 * Shared helpers for tests of the proofs and provenance a session records.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithProofs
{
    /**
     * Record a proof straight onto the session, as the session service would.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  \Carbon\CarbonInterface  $at
     * @param  list<string>  $methods
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     * @param  \SineMacula\Laravel\Authentication\Proofs\ObservedProperties  $observed
     * @return void
     */
    protected static function recordProof(
        EloquentSession&Model $session,
        ProofKind $kind,
        CarbonInterface $at,
        array $methods = [],
        ?Evaluation $evaluation = null,
        ObservedProperties $observed = new ObservedProperties,
    ): void {
        $purpose = match ($kind) {
            ProofKind::FIRST_FACTOR                                                        => Purpose::SIGN_IN,
            ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::EXTERNAL_REAUTHENTICATION => Purpose::REAUTHENTICATE,
            default                                                                        => Purpose::STEP_UP,
        };

        $proof = new NewProof($kind, $purpose, 'test', new Channel(ChannelKind::UNKNOWN), null, $observed, $evaluation, $methods, CarbonImmutable::instance($at)->startOfSecond());

        ProofWriter::record($session, (string) $session->getGuard(), $proof);
    }

    /**
     * Run the shipped proofs and provenance migrations.
     *
     * @return void
     */
    protected static function migrateProofTables(): void
    {
        foreach (['2026_04_06_000008_create_authentication_proofs_table.php', '2026_04_06_000009_create_authentication_provenance_table.php'] as $file) {
            ShippedMigrations::up($file);
        }
    }

    /**
     * The proofs the session records, oldest first (then by kind), as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return list<\SineMacula\Laravel\Authentication\Models\SessionProof>
     */
    protected static function proofsOf(EloquentSession $session): array
    {
        return array_values(SessionProof::query()
            ->where('session_id', IdentifierCoercion::stringify($session->getSessionIdentifier()))
            ->orderBy('authenticated_at')
            ->orderBy('kind')
            ->get()
            ->all());
    }

    /**
     * The provenance the session records, if any.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return ?\SineMacula\Laravel\Authentication\Models\SessionProvenance
     */
    protected static function provenanceOf(EloquentSession $session): ?SessionProvenance
    {
        return SessionProvenance::query()->find(IdentifierCoercion::stringify($session->getSessionIdentifier()));
    }

    /**
     * A further factor an adapter verified for the session or pending sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $application
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  ?\Carbon\CarbonInterface  $at
     * @param  \SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     * @param  list<string>  $methods
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind  $channel
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    protected static function adapterProof(
        Identity $identity,
        string $application,
        mixed $sessionId,
        Purpose $purpose = Purpose::STEP_UP,
        ProofKind $kind = ProofKind::ADDITIONAL_FACTOR,
        ?CarbonInterface $at = null,
        Evaluation $evaluation = new Evaluation(true, true),
        array $methods = ['otp'],
        ChannelKind $channel = ChannelKind::AUTHENTICATOR_APP,
    ): ProofResult {
        return new ProofResult(
            $kind,
            'totp',
            new Channel($channel),
            'factor-1',
            new ObservedProperties,
            $evaluation,
            $methods,
            $at ?? CarbonImmutable::now(),
            new ProofBinding($identity, $application, $sessionId, $purpose),
        );
    }
}
