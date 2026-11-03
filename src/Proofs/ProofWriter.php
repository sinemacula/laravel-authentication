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
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Records proofs and provenance on a session, in the caller's transaction on
 * the storage connection, where the session itself is written, voids the proofs
 * a removed factor made, and clears what an earlier session left under a new
 * session's key.
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
            'id'                   => $id ?? Str::uuid7()->toString(),
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
     * No evidence is recorded: nothing decides yet whether any is accepted.
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
            'link_id'                     => $provenance->linkId,
        ]);

        self::insert($row);
    }

    /**
     * Void the session's proofs made with the factor, so none of them counts
     * again: one `UPDATE` that marks every proof not voided yet that is bound
     * to the session as `record()` binds it (its key, the guard given and its
     * owner) and records that very factor reference, compared byte for byte.
     * Returns how many proofs it voided.
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
     * Delete every proof and provenance recorded under the new session's key,
     * before it records its own. A key the database issues again (an integer
     * key whose counter a truncation reset) would otherwise inherit what an
     * earlier session holding it left behind, which is bound to the same owner
     * and guard when the same identity signs in again.
     *
     * The rows are found with a plain read on the write connection and deleted
     * by their own keys only when there are any. A delete that matches nothing
     * locks the gap its key would go in on MySQL (InnoDB at REPEATABLE READ),
     * and a new session's key, time-ordered by default, falls in the last gap
     * of the proofs' and the provenance's indexes, so two sign-ins that each
     * held that lock and then inserted their own proof would deadlock. A plain
     * read takes no lock, and a delete by the key of a row that exists locks
     * only that row. Orphans under a new key were committed before the earlier
     * session's row was deleted (a proof is written under that row's lock), so
     * before the new row could be inserted, and nothing writes them
     * concurrently. The plain read sees them unless the transaction's snapshot
     * is older: on MySQL at REPEATABLE READ, a sign-in inside an application's
     * transaction whose first plain read came before they were committed does
     * not see them. Deleting a session's proofs with it, as pruning does, is
     * what keeps a reissued key clean; this is the second line.
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
