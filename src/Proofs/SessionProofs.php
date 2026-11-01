<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Reads a session's proofs, always on the write connection, so a lagging
 * replica cannot hide a proof just written, and always bounded, whatever the
 * session's age.
 *
 * Only the session's own proofs are read, bound to its key, guard and owner,
 * and only counting ones: one not voided, and, for a further factor or a
 * recovery code, one its adapter accepted (only accepted ones are stored, so
 * this is a second line). `history()` reads them in one aggregate query,
 * grouped by kind, `amr` values and multifactor report with each group's newest
 * time, so its rows are bounded by the distinct combinations the session
 * recorded rather than by how many it recorded. `newestMeeting()` reads the
 * newest one a freshness requirement takes, with `LIMIT 1`, on the proofs'
 * session, kind and time index.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionProofs
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * What the session's counting proofs say about its authentication.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofHistory
     *
     * @throws \InvalidArgumentException
     */
    public static function history(Session $session): ProofHistory
    {
        $model = new SessionProof;
        $at    = $model->getConnection()->getQueryGrammar()->wrap('authenticated_at');

        $rows = WriteConnection::during($model, static fn (): array => self::counting($session)
            ->toBase()
            ->select(['kind', 'methods', 'multifactor'])
            ->selectRaw("max({$at}) as newest")
            ->groupBy(['kind', 'methods', 'multifactor'])
            ->get()
            ->all());

        return new ProofHistory(array_values(array_map(static fn (object $row): array => self::summary($model, $row), $rows)));
    }

    /**
     * The newest of the session's counting proofs that meets the requirement at
     * the time given: of a kind it takes, made within its maximum age (from the
     * proof's own second until, and not including, the second the age after it,
     * so a proof made after now never meets it), and multifactor or phishing
     * resistant when it asks for either; `null` when none does.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    public static function newestMeeting(Session $session, FreshnessRequirement $requirement, CarbonImmutable $now): ?RecordedProof
    {
        $model = new SessionProof;

        $proof = WriteConnection::during($model, static fn (): mixed => self::counting($session)
            ->whereIn('kind', array_column($requirement->proofs, 'value'))
            ->where('authenticated_at', '>', $model->fromDateTime($now->subSeconds($requirement->maxAgeSeconds)))
            ->where('authenticated_at', '<=', $model->fromDateTime($now))
            ->when($requirement->multifactor, static fn (Builder $query): Builder => $query->where('multifactor', true))
            ->when($requirement->phishingResistant, static fn (Builder $query): Builder => $query->where('phishing_resistant', true))
            ->orderByDesc('authenticated_at')
            ->orderByDesc('id')
            ->first());

        return $proof instanceof SessionProof ? self::recorded($proof) : null;
    }

    /**
     * The query for the session's counting proofs, on the write PDO: those
     * bound to the session as it is now, its key, its guard and its owner, as
     * `ProofWriter` binds them, so another identity's or application's proof
     * under the same key never counts for it. A sign-in deletes what an earlier
     * session whose key it reuses left under it before recording its own
     * (`ProofWriter::clear()`, within the limit it states), so the same
     * identity's proofs from that earlier session do not count either. The
     * binding columns compare byte for byte, so a key or owner that differs
     * only in case is another.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\SessionProof>
     */
    private static function counting(Session $session): Builder
    {
        $additional  = [ProofKind::ADDITIONAL_FACTOR->value, ProofKind::RECOVERY_CODE->value];
        [$type, $id] = self::owner($session);

        return WriteConnection::query(SessionProof::query())
            ->where('session_id', IdentifierCoercion::stringify($session->getSessionIdentifier()) ?? '')
            ->where('guard', $session->getGuard() ?? '')
            ->where('authenticatable_type', $type)
            ->where('authenticatable_id', $id)
            ->whereNull('voided_at')
            ->where(static function (Builder $query) use ($additional): void {
                $query->whereNotIn('kind', $additional)->orWhere('accepted', true);
            });
    }

    /**
     * The owner's morph type and key the session records, as `ProofWriter`
     * writes them on its proofs; empty for a session that is not an Eloquent
     * session, which no proof is bound to. The columns are named by the
     * relation of a blank instance, so the recorded type is never instantiated.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return array{0: string, 1: string}
     */
    private static function owner(Session $session): array
    {
        if (!$session instanceof EloquentSession || !$session instanceof Model) {
            return ['', ''];
        }

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $blank */
        $blank = $session->newInstance();
        $owner = $blank->authenticatable();

        return [
            IdentifierCoercion::stringify($session->getAttribute($owner->getMorphType()))      ?? '',
            IdentifierCoercion::stringify($session->getAttribute($owner->getForeignKeyName())) ?? '',
        ];
    }

    /**
     * One summary row, as `ProofHistory` takes it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\SessionProof  $model
     * @param  object  $row
     * @return array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, at: \Carbon\CarbonImmutable}
     */
    private static function summary(SessionProof $model, object $row): array
    {
        $values = get_object_vars($row);
        $proof  = (clone $model)->setRawAttributes([
            'kind'             => $values['kind']        ?? null,
            'methods'          => $values['methods']     ?? null,
            'multifactor'      => $values['multifactor'] ?? null,
            'authenticated_at' => $values['newest']      ?? null,
        ]);

        return [
            'kind'        => ProofKind::from($proof->kind),
            'methods'     => AuthenticationMethods::kept($proof->methods),
            'multifactor' => $proof->multifactor === true,
            'at'          => CarbonImmutable::instance($proof->authenticated_at),
        ];
    }

    /**
     * The proof as callers read it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\SessionProof  $proof
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    private static function recorded(SessionProof $proof): RecordedProof
    {
        $evaluation = $proof->accepted === null || $proof->multifactor === null ? null : new Evaluation($proof->accepted, $proof->multifactor);

        $observed = new ObservedProperties(
            $proof->user_presence,
            $proof->user_verification,
            $proof->backup_eligible,
            $proof->backup_state,
            $proof->phishing_resistant,
            $proof->key_protection === null ? null : KeyProtection::from($proof->key_protection),
        );

        return new RecordedProof(
            $proof->id,
            ProofKind::from($proof->kind),
            Purpose::from($proof->purpose),
            $proof->method,
            new Channel(ChannelKind::from($proof->channel_kind), $proof->channel_reference),
            $proof->factor_reference,
            $observed,
            $evaluation,
            AuthenticationMethods::kept($proof->methods),
            CarbonImmutable::instance($proof->authenticated_at),
        );
    }
}
