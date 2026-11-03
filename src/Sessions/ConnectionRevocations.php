<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Ends the sessions an external provider's connection established, when the
 * connection is disabled or deleted, and an identity's sessions through one
 * link, when the link is removed or its scope is widened: every live session
 * (pending ones included, of every guard, unrevoked and before both deadlines)
 * whose provenance records the connection, and for a link that very link.
 *
 * A connection's sessions are found through the provenance's connection index,
 * and a link's through the identity's own sessions, 500 at a time, whose
 * provenance is then read by key and kept only when it records the connection
 * and the link; each chunk is locked in key order and revoked by the
 * conditional revocation write, all in one transaction on the session model's
 * connection, a savepoint inside the caller's. The provenance holds each key as
 * a string, so a connection's chunks follow the keys' own order (an integer
 * key's numeric one, not its string one): the locks the whole revocation holds
 * are then taken in one key order, as every other revocation takes them, and
 * two revocations of overlapping sessions never deadlock across a chunk. A
 * connection and a link are matched byte for byte, whatever the provenance
 * columns' collation, so one connection's or link's revocation never ends the
 * sessions of another whose id differs from it only in case, accents or a
 * trailing space; a session with no link recorded is never one of a link's. A
 * link's sessions, and their provenance, are found with locking reads (the
 * identity's live sessions locked in key order, as the revocation then locks
 * them), which read what is committed now rather than a snapshot the caller's
 * transaction opened earlier: on MySQL's REPEATABLE READ a plain read would
 * miss a session a sign-in through the link committed after the caller's first
 * read, though the caller's lock on the link made that sign-in wait for it.
 * Once that commits, the guard first forgets a binding to any session revoked,
 * so the rest of the request is not authenticated as a session it ended even
 * when a listener throws, and then `SessionRevoked` reports each one. No cutoff
 * moves: the scope is how the sessions began, not the identity. Each per-event
 * trigger can be turned off (`RevocationSettings`), and then writes nothing; a
 * link's widened scope cannot. A revocation called again finds nothing live
 * left to end, so it ends nothing and reports nothing more.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ConnectionRevocations
{
    /** @var int How many sessions one read takes. */
    public const int CHUNK = 500;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $writer
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard acting; its client is the events'. */
        private GuardContext $context,

        /** The guard's bound state, forgotten when the session it is bound to is revoked. */
        private GuardBinding $binding,

        /** Revokes each session and reports it once committed. */
        private RevocationWriter $writer,

        /** Defers forgetting the guard's binding until the revocation commits. */
        private AfterCommit $afterCommit,

        /** Container the configuration is resolved from. */
        private Container $container,
    ) {}

    /**
     * End every live session the connection established, with the reason of the
     * trigger (`connection_disabled` or `connection_deleted`), unless the
     * trigger is turned off. Returns how many sessions this call revoked.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function connection(string $connectionId, RevocationReason $reason, CarbonImmutable $now): int
    {
        self::assertNamed('A connection', $connectionId);

        if (!$this->isEnabled($reason)) {
            return 0;
        }

        $model   = SessionLookup::model();
        $numeric = $model->getKeyType() === 'int';

        return $model->getConnection()->transaction(function () use ($model, $numeric, $connectionId, $reason, $now): int {

            $ended   = $this->forgetOnCommit($model);
            $revoked = 0;
            $after   = null;

            do {
                $rows = self::established($connectionId, $after, $numeric);
                $revoked += $this->revoke($model, self::exactly($rows, $connectionId), null, $reason, $now, $ended);
                $after = $rows === [] ? null : IdentifierCoercion::stringify($rows[count($rows) - 1][0]);
            } while (count($rows) === self::CHUNK);

            return $revoked;
        });
    }

    /**
     * End every live session of the identity established through the link (the
     * connection and the link id given), with the reason of the trigger
     * (`link_removed`, unless that trigger is turned off, or
     * `link_scope_widened`, which no setting turns off). Returns how many
     * sessions this call revoked; an identity that is not an Eloquent model has
     * no sessions to end.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $linkId
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function link(Identity $identity, string $connectionId, string $linkId, RevocationReason $reason, CarbonImmutable $now): int
    {
        self::assertNamed('A connection', $connectionId);
        self::assertNamed('A link', $linkId);

        if (!$this->isEnabled($reason) || !$identity instanceof Model) {
            return 0;
        }

        $model = SessionLookup::model();

        return $model->getConnection()->transaction(function () use ($model, $identity, $connectionId, $linkId, $reason, $now): int {

            $ended   = $this->forgetOnCommit($model);
            $revoked = 0;
            $after   = null;

            do {
                $keys = self::owned($model, $identity, $after, $now);
                $revoked += $this->revoke($model, self::through($keys, $connectionId, $linkId), $identity, $reason, $now, $ended);
                $after = $keys === [] ? null : $keys[count($keys) - 1];
            } while (count($keys) === self::CHUNK);

            return $revoked;
        });
    }

    /**
     * Refuse an empty id: a connection or a link is named by its id.
     *
     * @param  string  $what
     * @param  string  $id
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertNamed(string $what, string $id): void
    {
        if ($id === '') {
            throw new \InvalidArgumentException(sprintf('%s is named by its id, which may not be empty.', $what));
        }
    }

    /**
     * Whether the trigger ends sessions: its setting, or always for one no
     * setting turns off.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function isEnabled(RevocationReason $reason): bool
    {
        return (new RevocationSettings($this->container->make(Repository::class)))->isEnabled($reason);
    }

    /**
     * The next chunk of the provenance rows of the connection, after the key
     * given, in key order, as `[session key, connection id]`, read from the
     * provenance's connection index on the write connection. The index finds
     * them under the column's collation; `exactly()` keeps those that name the
     * connection byte for byte. Integer keys, held as strings, are ordered by
     * length and then as strings, which is their numeric order.
     *
     * @param  string  $connectionId
     * @param  ?string  $after
     * @param  bool  $numeric
     * @return list<array{0: mixed, 1: mixed}>
     */
    private static function established(string $connectionId, ?string $after, bool $numeric): array
    {
        $query  = WriteConnection::query(SessionProvenance::query());
        $length = 'length(' . $query->getQuery()->getGrammar()->wrap('session_id') . ')';

        $query->where('connection_id', $connectionId)
            ->when($after !== null && $numeric, static fn (Builder $query): Builder => self::numericallyAfter($query, $length, (string) $after))
            ->when($after !== null && !$numeric, static fn (Builder $query): Builder => $query->where('session_id', '>', $after))
            ->when($numeric, static fn (Builder $query): Builder => $query->orderByRaw($length))
            ->orderBy('session_id')
            ->limit(self::CHUNK);

        return self::provenance($query);
    }

    /**
     * Hold the query to the provenance of integer keys after the key given, in
     * their numeric order: longer ones, or ones as long that sort after it.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\SessionProvenance>  $query
     * @param  string  $length
     * @param  string  $after
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\SessionProvenance>
     */
    private static function numericallyAfter(Builder $query, string $length, string $after): Builder
    {
        return $query->where(static function (Builder $query) use ($length, $after): void {
            $query->whereRaw($length . ' > ?', [strlen($after)])
                ->orWhere(static function (Builder $query) use ($length, $after): void {
                    $query->whereRaw($length . ' = ?', [strlen($after)])->where('session_id', '>', $after);
                });
        });
    }

    /**
     * The next chunk of the keys of the identity's live sessions, after the key
     * given, in key order, read on the write connection with a locking read, so
     * it sees every session committed by now and holds each one, in key order,
     * until the revocation's transaction ends.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @param  ?string  $after
     * @param  \Carbon\CarbonImmutable  $now
     * @return list<string>
     */
    private static function owned(EloquentSession&Model $model, Model $identity, ?string $after, CarbonImmutable $now): array
    {
        $owner = $model->authenticatable();
        $query = self::live(WriteConnection::query($model->newQuery()), $model, $now)
            ->where($owner->getMorphType(), $identity->getMorphClass())
            ->where($owner->getForeignKeyName(), IdentifierCoercion::stringify($identity->getKey()))
            ->when($after !== null, static fn (Builder $query): Builder => $query->where($model->getKeyName(), '>', $after))
            ->orderBy($model->getKeyName())
            ->limit(self::CHUNK)
            ->lockForUpdate();

        return self::strings(WriteConnection::during($model, static fn (): array => $query->pluck($model->getKeyName())->all()));
    }

    /**
     * Those of the session keys established through the link (the connection
     * and the link id given), read from the provenance on the write connection
     * with a locking read, so a provenance committed with its session after the
     * caller's transaction first read is seen, and kept only when both match
     * byte for byte.
     *
     * @param  list<string>  $keys
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return list<string>
     */
    private static function through(array $keys, string $connectionId, string $linkId): array
    {
        if ($keys === []) {
            return [];
        }

        $query = WriteConnection::query(SessionProvenance::query())->whereKey($keys)->where('connection_id', $connectionId)->where('link_id', $linkId)->sharedLock();

        /** @var list<\stdClass> $rows */
        $rows = WriteConnection::during(new SessionProvenance, static fn (): array => $query->toBase()->get(['session_id', 'connection_id', 'link_id'])->all());
        $kept = array_filter($rows, static fn (\stdClass $row): bool => $row->connection_id === $connectionId && $row->link_id === $linkId);

        return self::strings(array_column($kept, 'session_id'));
    }

    /**
     * The provenance rows the query finds, as `[session key, connection id]` as
     * stored, read on the write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\SessionProvenance>  $query
     * @return list<array{0: mixed, 1: mixed}>
     */
    private static function provenance(Builder $query): array
    {
        /** @var list<\stdClass> $rows */
        $rows = WriteConnection::during(new SessionProvenance, static fn (): array => $query->toBase()->get(['session_id', 'connection_id'])->all());

        return array_map(static fn (\stdClass $row): array => [$row->session_id, $row->connection_id], $rows);
    }

    /**
     * The session keys, each as a string, of the provenance rows that name the
     * connection byte for byte, so a column whose collation counts another
     * connection's id as equal (another case or accent, a trailing space) never
     * ends that connection's sessions.
     *
     * @param  list<array{0: mixed, 1: mixed}>  $rows
     * @param  string  $connectionId
     * @return list<string>
     */
    private static function exactly(array $rows, string $connectionId): array
    {
        $keys = [];

        foreach ($rows as [$key, $recorded]) {
            if ($recorded !== $connectionId) {
                continue;
            }

            $keys[] = $key;
        }

        return self::strings($keys);
    }

    /**
     * Once the revocation commits, before any session it revoked is reported,
     * forget the guard's binding to whichever of them it is bound to: Laravel
     * runs a commit's callbacks in order without catching, so a report listener
     * that throws would otherwise leave the binding to the sessions reported
     * after it. Answers the list each session revoked is added to.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @return \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>
     */
    private function forgetOnCommit(EloquentSession&Model $model): \ArrayObject
    {
        /** @var \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> $ended */
        $ended   = new \ArrayObject;
        $binding = $this->binding;

        $this->afterCommit->run($model, static function () use ($binding, $ended): void {
            foreach ($ended as $session) {
                $binding->forgetSession($session);
            }
        });

        return $ended;
    }

    /**
     * Lock the live sessions with the keys given, in key order, and revoke each
     * with the reason, adding it to the sessions whose binding is forgotten and
     * reporting it once committed. Returns how many this call revoked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  list<string>  $keys
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \ArrayObject<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>  $ended
     * @return int
     */
    private function revoke(EloquentSession&Model $model, array $keys, ?Identity $identity, RevocationReason $reason, CarbonImmutable $now, \ArrayObject $ended): int
    {
        if ($keys === []) {
            return 0;
        }

        $query = self::live(WriteConnection::query($model->newQuery()), $model, $now)->whereKey($keys)->orderBy($model->getKeyName())->lockForUpdate();

        /** @var list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> $sessions */
        $sessions = WriteConnection::during($model, static fn (): array => $query->get()->all());
        $revoked  = array_filter($sessions, function (EloquentSession&Model $session) use ($identity, $reason, $now): bool {

            $context = new EventContext($session->getGuard(), $this->context->client(), $identity, session: $session, method: $session->getSignInMethod(), fromSession: true);
            $event   = new SessionRevoked($context, $reason);

            return $this->writer->revoke($session, $reason, $now, fn () => $this->context->dispatch($event));
        });

        foreach ($revoked as $session) {
            $ended->append($session);
        }

        return count($revoked);
    }

    /**
     * Hold the query to live sessions: unrevoked, and before both deadlines at
     * `$now`, whatever their status, so a session that has already ended
     * (waiting to be pruned) is neither revoked nor counted.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model
     *
     * @param  \Illuminate\Database\Eloquent\Builder<TModel>  $query
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  \Carbon\CarbonImmutable  $now
     * @return \Illuminate\Database\Eloquent\Builder<TModel>
     */
    private static function live(Builder $query, EloquentSession&Model $model, CarbonImmutable $now): Builder
    {
        $at       = $model->fromDateTime($now);
        $absolute = $model->getAbsoluteExpiresAtName();

        return $query->whereNull($model->getRevokedAtName())
            ->where($model->getIdleExpiresAtName(), '>', $at)
            ->where(static function (Builder $query) use ($absolute, $at): void {
                $query->whereNull($absolute)->orWhere($absolute, '>', $at);
            });
    }

    /**
     * The keys read, each as a string.
     *
     * @param  array<array-key, mixed>  $keys
     * @return list<string>
     */
    private static function strings(array $keys): array
    {
        $strings = array_map(static fn (mixed $key): ?string => IdentifierCoercion::stringify($key), $keys);

        return array_values(array_filter($strings, static fn (?string $key): bool => $key !== null));
    }
}
