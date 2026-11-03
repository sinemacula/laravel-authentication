<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
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
 * grouped by kind, `amr` values, multifactor report, additional verification
 * and acceptance with each group's newest time, so its rows are bounded by the
 * distinct combinations the session recorded rather than by how many it
 * recorded. `newestMeeting()` reads the newest one a freshness requirement
 * takes, with `LIMIT 1`, on the proofs' session, kind and time index. `query()`
 * reads a bounded page of them for a requirement check, `firstFactor()` the
 * first factor the session signed in with, `connectionId()` the connection its
 * provenance records, and `provenance()` the whole provenance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionProofs
{
    /** @var int The most proofs carrying evidence one read of the accepted evidence takes. */
    public const int EVIDENCE_LIMIT = 50;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * What the session's counting proofs say about its authentication.
     *
     * `$current` reads what is committed now rather than what the transaction's
     * snapshot holds, for an issuance that has written the session's issuance
     * guard: on MySQL and MariaDB, whose plain reads inside a REPEATABLE READ
     * transaction return the snapshot of its first read, with a shared lock on
     * the rows read, held until the transaction ends. Every other engine reads
     * as it does without: PostgreSQL refuses a shared lock on a grouped read,
     * and needs none, since at READ COMMITTED each statement reads what is
     * committed once the guard has waited for any writer of the session still
     * in flight, and at REPEATABLE READ the guard fails to serialise when one
     * committed after the snapshot; SQLite lets one writer in at a time.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofHistory
     *
     * @throws \InvalidArgumentException
     */
    public static function history(Session $session, bool $current = false): ProofHistory
    {
        $model  = new SessionProof;
        $at     = $model->getConnection()->getQueryGrammar()->wrap('authenticated_at');
        $shared = $current && in_array($model->getConnection()->getDriverName(), ['mysql', 'mariadb'], true);

        $rows = WriteConnection::during($model, static fn (): array => self::counting($session)
            ->toBase()
            ->select(['kind', 'methods', 'multifactor', 'additional_verification', 'accepted'])
            ->selectRaw("max({$at}) as newest")
            ->groupBy(['kind', 'methods', 'multifactor', 'additional_verification', 'accepted'])
            ->when($shared, static fn (QueryBuilder $query): QueryBuilder => $query->sharedLock())
            ->get()
            ->all());

        return new ProofHistory(array_map(static fn (object $row): array => self::summary($model, $row), $rows));
    }

    /**
     * The newest of the session's counting proofs that meets the requirement at
     * the time given: of a kind it takes, made within its maximum age (from the
     * proof's own second until, and not including, the second the age after it,
     * so a proof made after now never meets it), and multifactor or phishing
     * resistant when it asks for either; `null` when none does. A proof that
     * carries an external provider's evidence never meets one that asks for
     * multifactor authentication: the evidence was accepted as of any age, and
     * the proof is timed when the provider authenticated the identity, not when
     * that evidence is from, so freshness takes no provider's evidence. With a
     * factor excluded, a proof made with that factor (its factor reference,
     * compared byte for byte) never meets it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?string  $excludingFactor
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    public static function newestMeeting(Session $session, FreshnessRequirement $requirement, CarbonImmutable $now, ?string $excludingFactor = null): ?RecordedProof
    {
        $model = new SessionProof;

        $proof = WriteConnection::during($model, static fn (): mixed => self::counting($session)
            ->whereIn('kind', array_column($requirement->proofs, 'value'))
            ->when($excludingFactor !== null, static fn (Builder $query): Builder => $query->where(
                static fn (Builder $factor): Builder => $factor->whereNull('factor_reference')->orWhere('factor_reference', '<>', $excludingFactor),
            ))
            ->where('authenticated_at', '>', $model->fromDateTime($now->subSeconds($requirement->maxAgeSeconds)))
            ->where('authenticated_at', '<=', $model->fromDateTime($now))
            ->when($requirement->multifactor, static fn (Builder $query): Builder => $query->where('multifactor', true)->whereNull('evidence'))
            ->when($requirement->phishingResistant, static fn (Builder $query): Builder => $query->where('phishing_resistant', true))
            ->orderByDesc('authenticated_at')
            ->orderByDesc('id')
            ->first());

        return $proof instanceof SessionProof ? self::recorded($proof) : null;
    }

    /**
     * The session's counting proofs, newest first by time and then by id, only
     * those made at or after `$since` when it is given and of the given kinds
     * when they are, at most `$limit` of them: one `LIMIT` query on the proofs'
     * session, kind and time index.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\Carbon\CarbonImmutable  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     */
    public static function query(Session $session, ?CarbonImmutable $since, ?array $kinds, int $limit): array
    {
        $model = new SessionProof;

        $proofs = WriteConnection::during($model, static fn (): array => self::counting($session)
            ->when($since !== null, static fn (Builder $query): Builder => $query->where('authenticated_at', '>=', $model->fromDateTime($since)))
            ->when($kinds !== null, static fn (Builder $query): Builder => $query->whereIn('kind', array_column($kinds ?? [], 'value')))
            ->orderByDesc('authenticated_at')
            ->orderByDesc('id')
            ->limit($limit)
            ->get()
            ->all());

        return array_values(array_map(self::recorded(...), $proofs));
    }

    /**
     * The first factor the session signed in with: its oldest counting
     * first-factor proof, or `null` for a session that records none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    public static function firstFactor(Session $session): ?RecordedProof
    {
        $proof = WriteConnection::during(new SessionProof, static fn (): mixed => self::counting($session)
            ->where('kind', ProofKind::FIRST_FACTOR->value)
            ->orderBy('authenticated_at')
            ->orderBy('id')
            ->first());

        return $proof instanceof SessionProof ? self::recorded($proof) : null;
    }

    /**
     * The evidence an external provider asserted for the session and the
     * evidence contract accepted, among its counting proofs that carry any (its
     * external first factor and its external reauthentications), newest by the
     * evidence's own time first, and of evidence asserting the same methods and
     * context only the newest, which an older copy can never better: one
     * bounded read of at most `EVIDENCE_LIMIT` of those proofs, newest first,
     * on the proofs' session index. Evidence a row holds malformed is no
     * evidence.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return list<\SineMacula\Laravel\Authentication\External\ExternalEvidence>
     */
    public static function acceptedEvidence(Session $session): array
    {
        $stored = WriteConnection::during(new SessionProof, static fn (): array => self::counting($session)
            ->whereIn('kind', [ProofKind::FIRST_FACTOR->value, ProofKind::EXTERNAL_REAUTHENTICATION->value])
            ->whereNotNull('evidence')
            ->orderByDesc('authenticated_at')
            ->orderByDesc('id')
            ->limit(self::EVIDENCE_LIMIT)
            ->get(['evidence'])
            ->all());

        $newest = [];

        foreach ($stored as $proof) {
            $evidence = ExternalEvidence::fromStored($proof->evidence);

            if ($evidence === null) {
                continue;
            }

            $asserted = serialize([$evidence->methods, $evidence->context]);
            $kept     = $newest[$asserted] ?? null;

            $newest[$asserted] = $kept === null || $evidence->authenticatedAt->greaterThan($kept->authenticatedAt) ? $evidence : $kept;
        }

        usort($newest, static fn (ExternalEvidence $one, ExternalEvidence $other): int => $other->authenticatedAt->getTimestamp() <=> $one->authenticatedAt->getTimestamp());

        return $newest;
    }

    /**
     * The connection the session's provenance records it was established
     * through, or `null` for a session no external provider established.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?string
     */
    public static function connectionId(Session $session): ?string
    {
        $key = IdentifierCoercion::stringify($session->getSessionIdentifier()) ?? '';

        return WriteConnection::during(new SessionProvenance, static fn (): ?string => IdentifierCoercion::stringify(
            WriteConnection::query(SessionProvenance::query())->whereKey($key)->value('connection_id'),
        ));
    }

    /**
     * The provenance the session records, read on the write connection, or
     * `null` for a session no external provider established.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Provenance
     *
     * @throws \InvalidArgumentException
     */
    public static function provenance(Session $session): ?Provenance
    {
        $key = IdentifierCoercion::stringify($session->getSessionIdentifier()) ?? '';

        $row = WriteConnection::during(new SessionProvenance, static fn (): mixed => WriteConnection::query(SessionProvenance::query())->whereKey($key)->first());

        return $row instanceof SessionProvenance ? new Provenance(
            $row->connection_id,
            $row->tenant_id,
            $row->provider_authenticated_at,
            $row->provider_session_expires_at,
            $row->policy_version,
            $row->link_id,
            ExternalEvidence::fromStored($row->accepted_evidence),
        ) : null;
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
     * only in case or by a trailing space is another.
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
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Models\SessionProof  $model
     * @param  object  $row
     * @return array{kind: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, methods: list<string>, multifactor: bool, additional: bool, accepted: bool, at: \Carbon\CarbonImmutable}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function summary(SessionProof $model, object $row): array
    {
        $values = get_object_vars($row);
        $proof  = (clone $model)->setRawAttributes([
            'kind'                    => $values['kind']                    ?? null,
            'methods'                 => $values['methods']                 ?? null,
            'multifactor'             => $values['multifactor']             ?? null,
            'additional_verification' => $values['additional_verification'] ?? null,
            'accepted'                => $values['accepted']                ?? null,
            'authenticated_at'        => $values['newest']                  ?? null,
        ]);

        return [
            'kind'        => ProofKind::from($proof->kind),
            'methods'     => AuthenticationMethods::kept($proof->methods),
            'multifactor' => $proof->multifactor             === true,
            'additional'  => $proof->additional_verification === true,
            'accepted'    => $proof->accepted                === true,
            'at'          => CarbonImmutable::instance($proof->authenticated_at),
        ];
    }

    /**
     * The proof as callers read it; an external proof reads back with no
     * evaluation, as `RecordedProof` explains.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\SessionProof  $proof
     * @return \SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    private static function recorded(SessionProof $proof): RecordedProof
    {
        $external   = $proof->channel_kind          === ChannelKind::EXTERNAL_PROVIDER->value;
        $evaluation = $external || $proof->accepted === null || $proof->multifactor === null
            ? null
            : new Evaluation($proof->accepted, $proof->multifactor, $proof->additional_verification === true);

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
            ExternalEvidence::fromStored($proof->evidence),
        );
    }
}
