<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Builder as QueryBuilder;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\GrammarExpression;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ProviderContext;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Reads a session's counting proofs and provenance, always on the write
 * connection and always bounded.
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
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofHistory
     *
     * @throws \InvalidArgumentException
     */
    public static function history(Session $session, bool $current = false): ProofHistory
    {
        $model  = new SessionProof;
        $shared = self::sharesLock($model, $current);

        $rows = WriteConnection::during($model, static fn (): array => self::counting($session)
            ->toBase()
            ->select(['kind', 'methods', 'multifactor', 'additional_verification', 'accepted'])
            ->addSelect(new GrammarExpression('max(%s) as newest', ['authenticated_at']))
            ->groupBy(['kind', 'methods', 'multifactor', 'additional_verification', 'accepted'])
            ->when($shared, static fn (QueryBuilder $query): QueryBuilder => $query->sharedLock())
            ->get()
            ->all());

        return new ProofHistory(array_values(array_map(static fn (object $row): array => self::summary($model, $row), $rows)));
    }

    /**
     * The newest of the session's counting proofs that meets the freshness
     * requirement at the time given, or `null` when none does.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement  $requirement
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?string  $excludingFactor
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    public static function newestMeeting(
        Session $session,
        FreshnessRequirement $requirement,
        CarbonImmutable $now,
        ?string $excludingFactor = null,
        bool $current = false,
    ): ?RecordedProof {
        $model  = new SessionProof;
        $shared = self::sharesLock($model, $current);

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
            ->orderByDesc('sequence')
            ->when($shared, static fn (Builder $query): Builder => $query->sharedLock())
            ->first());

        return $proof instanceof SessionProof ? self::recorded($proof) : null;
    }

    /**
     * A page of the session's counting proofs, newest first, filtered by time
     * and kind when given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\Carbon\CarbonInterface  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @param  bool  $current
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     */
    public static function query(Session $session, ?CarbonInterface $since, ?array $kinds, int $limit, bool $current = false): array
    {
        $model  = new SessionProof;
        $shared = self::sharesLock($model, $current);
        $from   = $since?->toImmutable()->setTimezone(date_default_timezone_get());

        $proofs = WriteConnection::during($model, static fn (): array => self::counting($session)
            ->when($from !== null, static fn (Builder $query): Builder => $query->where('authenticated_at', '>=', $model->fromDateTime($from)))
            ->when($kinds !== null, static fn (Builder $query): Builder => $query->whereIn('kind', array_column($kinds ?? [], 'value')))
            ->orderByDesc('authenticated_at')
            ->orderByDesc('sequence')
            ->limit($limit)
            ->when($shared, static fn (Builder $query): Builder => $query->sharedLock())
            ->get()
            ->all());

        return array_values(array_map(self::recorded(...), $proofs));
    }

    /**
     * The first factor the session signed in with, or `null` for a session that
     * records none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     */
    public static function firstFactor(Session $session, bool $current = false): ?RecordedProof
    {
        $model  = new SessionProof;
        $shared = self::sharesLock($model, $current);

        $proof = WriteConnection::during($model, static fn (): mixed => self::counting($session)
            ->where('kind', ProofKind::FIRST_FACTOR->value)
            ->orderBy('authenticated_at')
            ->orderBy('sequence')
            ->when($shared, static fn (Builder $query): Builder => $query->sharedLock())
            ->first());

        return $proof instanceof SessionProof ? self::recorded($proof) : null;
    }

    /**
     * The accepted external evidence the session's proofs hold, newest first,
     * keeping only the newest copy of each assertion.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return list<\SineMacula\Laravel\Authentication\External\ExternalEvidence>
     */
    public static function acceptedEvidence(Session $session, bool $current = false): array
    {
        $model  = new SessionProof;
        $shared = self::sharesLock($model, $current);

        $stored = WriteConnection::during($model, static fn (): array => self::counting($session)
            ->whereIn('kind', [ProofKind::FIRST_FACTOR->value, ProofKind::EXTERNAL_REAUTHENTICATION->value])
            ->whereNotNull('evidence')
            ->orderByDesc('authenticated_at')
            ->orderByDesc('sequence')
            ->limit(self::EVIDENCE_LIMIT)
            ->when($shared, static fn (Builder $query): Builder => $query->sharedLock())
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
     * The connection the session was established through, or `null` for a
     * session no external provider established.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return ?string
     */
    public static function connectionId(Session $session, bool $current = false): ?string
    {
        $key    = IdentifierCoercion::stringify($session->getSessionIdentifier()) ?? '';
        $model  = new SessionProvenance;
        $shared = self::sharesLock($model, $current);

        return WriteConnection::during($model, static fn (): ?string => IdentifierCoercion::stringify(
            WriteConnection::query(SessionProvenance::query())
                ->whereKey($key)
                ->when($shared, static fn (Builder $query): Builder => $query->sharedLock())
                ->value('connection_id'),
        ));
    }

    /**
     * The provenance the session records, or `null` for a session no external
     * provider established.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $current
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Provenance
     *
     * @throws \InvalidArgumentException
     */
    public static function provenance(Session $session, bool $current = false): ?Provenance
    {
        $key    = IdentifierCoercion::stringify($session->getSessionIdentifier()) ?? '';
        $model  = new SessionProvenance;
        $shared = self::sharesLock($model, $current);

        $row = WriteConnection::during($model, static fn (): mixed => WriteConnection::query(SessionProvenance::query())
            ->whereKey($key)
            ->when($shared, static fn (Builder $query): Builder => $query->sharedLock())
            ->first());

        return $row instanceof SessionProvenance ? new Provenance(
            $row->connection_id,
            $row->tenant_id,
            $row->provider_authenticated_at,
            $row->provider_session_expires_at,
            $row->policy_version,
            $row->link_id,
            ExternalEvidence::fromStored($row->accepted_evidence),
            ProviderContext::fromStored($row->provider_context),
        ) : null;
    }

    /**
     * Whether a current read takes a shared lock: only MySQL and MariaDB need
     * one, since their reads otherwise return the transaction's snapshot.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  bool  $current
     * @return bool
     */
    private static function sharesLock(Model $model, bool $current): bool
    {
        return $current && in_array($model->getConnection()->getDriverName(), ['mysql', 'mariadb'], true);
    }

    /**
     * The query for the session's counting proofs, bound to its key, guard and
     * owner.
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
     * The owner's morph type and key the session records, empty for a session
     * that is not an Eloquent session.
     *
     * The relation is read off a blank instance so the recorded type is never
     * instantiated.
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
     * evaluation.
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
