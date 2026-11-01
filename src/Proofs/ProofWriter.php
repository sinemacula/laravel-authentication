<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Records proofs and provenance on a session, in the caller's transaction on
 * the storage connection, where the session itself is written.
 *
 * A proof's binding is the session it is recorded on: its owner (the identity),
 * its guard (the application) and its key; the purpose is the proof's own.
 * Every time is kept to the whole second, in the application's time zone, as
 * the session's own times are.
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
     * Record the proof on the session, of the guard given.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Proofs\NewProof  $proof
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function record(EloquentSession&Model $session, string $guard, NewProof $proof): void
    {
        $owner    = $session->authenticatable();
        $observed = $proof->observed;
        $row      = new SessionProof;

        $row->forceFill([
            'id'                   => Str::uuid7()->toString(),
            'session_id'           => self::sessionId($session),
            'kind'                 => $proof->kind->value,
            'purpose'              => $proof->purpose->value,
            'method'               => $proof->method,
            'channel_kind'         => $proof->channel->kind->value,
            'channel_reference'    => $proof->channel->reference,
            'factor_reference'     => $proof->factor,
            'user_presence'        => $observed->userPresence,
            'user_verification'    => $observed->userVerification,
            'backup_eligible'      => $observed->backupEligible,
            'backup_state'         => $observed->backupState,
            'phishing_resistant'   => $observed->phishingResistant,
            'key_protection'       => $observed->keyProtection?->value,
            'accepted'             => $proof->evaluation?->accepted,
            'multifactor'          => $proof->evaluation?->multifactor,
            'methods'              => $proof->methods,
            'authenticatable_type' => $session->getAttribute($owner->getMorphType()),
            'authenticatable_id'   => IdentifierCoercion::stringify($session->getAttribute($owner->getForeignKeyName())),
            'guard'                => $guard,
            'authenticated_at'     => self::local($proof->authenticatedAt),
        ]);

        self::insert($row);
    }

    /**
     * Record how the session, established through an external provider, began.
     * No evidence is recorded: only the evidence contract may accept any.
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
            'accepted_evidence'           => null,
            'provider_session_expires_at' => self::local($provenance->sessionNotAfter),
            'policy_version'              => $provenance->policyVersion,
        ]);

        self::insert($row);
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
     * written in, or `null`.
     *
     * @param  ?\Carbon\CarbonInterface  $time
     * @return ?\Carbon\CarbonInterface
     */
    private static function local(?CarbonInterface $time): ?CarbonInterface
    {
        return $time?->toImmutable()->setTimezone(date_default_timezone_get());
    }

    /**
     * Insert the row, or throw when a model event cancelled the insert, so the
     * session written with it is rolled back rather than left without it.
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
