<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Writes, voids and clears the proofs and provenance recorded on a session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ProofWriter
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Record the proof on the session, of the guard given, under the id given
     * (one already judged in memory) or a new one.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Proofs\NewProof  $proof
     * @param  ?string  $id
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function record(EloquentSession&Model $session, string $guard, NewProof $proof, ?string $id = null): void
    {
        $owner    = $session->authenticatable();
        $observed = $proof->observed;
        $row      = new SessionProof;

        $row->forceFill([
            'id'                      => $id ?? Str::uuid7()->toString(),
            'session_id'              => self::sessionId($session),
            'kind'                    => $proof->kind->value,
            'purpose'                 => $proof->purpose->value,
            'method'                  => $proof->method,
            'channel_kind'            => $proof->channel->kind->value,
            'channel_reference'       => $proof->channel->reference,
            'factor_reference'        => $proof->factor,
            'user_presence'           => $observed->userPresence,
            'user_verification'       => $observed->userVerification,
            'backup_eligible'         => $observed->backupEligible,
            'backup_state'            => $observed->backupState,
            'phishing_resistant'      => $observed->phishingResistant,
            'key_protection'          => $observed->keyProtection?->value,
            'accepted'                => $proof->evaluation?->accepted,
            'multifactor'             => $proof->evaluation?->multifactor,
            'additional_verification' => self::isAdditionalVerification($proof),
            'evidence'                => $proof->evidence?->toArray(),
            'methods'                 => $proof->methods,
            'authenticatable_type'    => $session->getAttribute($owner->getMorphType()),
            'authenticatable_id'      => IdentifierCoercion::stringify($session->getAttribute($owner->getForeignKeyName())),
            'guard'                   => $guard,
            'authenticated_at'        => self::local($proof->authenticatedAt),
        ]);

        self::insert($row);
    }

    /**
     * Record how the session, established through an external provider, began.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Proofs\Provenance  $provenance
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function provenance(EloquentSession&Model $session, Provenance $provenance): void
    {
        $row = new SessionProvenance;

        $row->forceFill([
            'session_id'                  => self::sessionId($session),
            'connection_id'               => $provenance->connectionId,
            'tenant_id'                   => $provenance->tenantId,
            'provider_authenticated_at'   => self::local($provenance->providerAuthenticatedAt),
            'accepted_evidence'           => $provenance->evidence?->toArray(),
            'provider_session_expires_at' => self::local($provenance->sessionNotAfter),
            'policy_version'              => $provenance->policyVersion,
            'link_id'                     => $provenance->linkId,
            'provider_context'            => $provenance->providerContext?->toStored(),
        ]);

        self::insert($row);
    }

    /**
     * Void the session's proofs made with the factor, returning how many it
     * voided.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @param  string  $factor
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \LogicException
     */
    public static function void(EloquentSession&Model $session, string $guard, string $factor, CarbonImmutable $now): int
    {
        $owner = $session->authenticatable();
        $model = new SessionProof;

        return $model->newQuery()
            ->where('session_id', self::sessionId($session))
            ->where('guard', $guard)
            ->where('authenticatable_type', $session->getAttribute($owner->getMorphType()))
            ->where('authenticatable_id', IdentifierCoercion::stringify($session->getAttribute($owner->getForeignKeyName())))
            ->where('factor_reference', $factor)
            ->whereNull('voided_at')
            ->update(['voided_at' => $model->fromDateTime(self::local($now))]);
    }

    /**
     * Delete any proofs and provenance an earlier session left under the new
     * session's key.
     *
     * Read before deleting by key: on MySQL a delete matching nothing
     * gap-locks, so two concurrent sign-ins would deadlock.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return void
     *
     * @throws \LogicException
     */
    public static function clear(EloquentSession&Model $session): void
    {
        $sessionId = self::sessionId($session);
        $proofs    = WriteConnection::query((new SessionProof)->newQuery()->where('session_id', $sessionId))->pluck('id')->all();

        if ($proofs !== []) {
            (new SessionProof)->newQuery()->whereKey($proofs)->delete();
        }

        if (!WriteConnection::query((new SessionProvenance)->newQuery()->whereKey($sessionId))->exists()) {
            return;
        }

        (new SessionProvenance)->newQuery()->whereKey($sessionId)->delete();
    }

    /**
     * Whether the proof is recorded as an additional verification, or `null`
     * for a proof without an evaluation.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\NewProof  $proof
     * @return ?bool
     */
    private static function isAdditionalVerification(NewProof $proof): ?bool
    {
        $evaluation = $proof->evaluation;

        if ($evaluation === null) {
            return null;
        }

        return match ($proof->kind) {
            ProofKind::ADDITIONAL_FACTOR => true,
            ProofKind::RECOVERY_CODE     => false,
            default                      => $evaluation->additionalVerification,
        };
    }

    /**
     * The session's key as the proofs and provenance record it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @return string
     *
     * @throws \LogicException
     */
    private static function sessionId(EloquentSession&Model $session): string
    {
        return IdentifierCoercion::stringify($session->getSessionIdentifier())
            ?? throw new \LogicException('A proof can only be recorded on a session that has a key.');
    }

    /**
     * The time in the application's time zone, the one the session's times are
     * written in.
     *
     * @param  ?\Carbon\CarbonInterface  $time
     * @return ?\Carbon\CarbonInterface
     */
    private static function local(?CarbonInterface $time): ?CarbonInterface
    {
        return $time?->toImmutable()->setTimezone(date_default_timezone_get());
    }

    /**
     * Insert the row, or throw when a model event cancelled the insert.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $row
     * @return void
     *
     * @throws \LogicException
     */
    private static function insert(Model $row): void
    {
        if (!$row->save()) {
            throw new \LogicException(sprintf('%s was not saved: a model event cancelled it, so the session it belongs to is not written.', $row::class));
        }
    }
}
