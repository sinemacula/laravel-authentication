<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
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
 * connection is disabled or deleted, and an identity's sessions through it when
 * the identity's link to it is removed: every live session (pending ones
 * included, of every guard, unrevoked and before both deadlines) whose
 * provenance records the connection.
 *
 * A connection's sessions are found through the provenance's connection index,
 * and a link's through the identity's own sessions, 500 at a time; each chunk
 * is locked in key order and revoked by the conditional revocation write, all
 * in one transaction on the session model's connection, a savepoint inside the
 * caller's. A connection is matched byte for byte, whatever the provenance
 * column's collation, so one connection's revocation never ends the sessions of
 * another whose id differs from it only in case, accents or a trailing space.
 * `SessionRevoked` reports each session revoked once that commits. No cutoff
 * moves: the scope is how the sessions began, not the identity. Each trigger
 * can be turned off (`RevocationSettings`), and then writes nothing.
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
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $writer
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard acting; its client is the events'. */
        private GuardContext $context,

        /** Revokes each session and reports it once committed. */
        private RevocationWriter $writer,

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
        if (!$this->isEnabled($connectionId, $reason)) {
            return 0;
        }

        $model = SessionLookup::model();

        return $model->getConnection()->transaction(function () use ($model, $connectionId, $reason, $now): int {

            $revoked = 0;
            $after   = null;

            do {
                $rows = self::established($connectionId, $after);
                $revoked += $this->revoke($model, self::exactly($rows, $connectionId), null, $reason, $now);
                $after = $rows === [] ? null : $rows[count($rows) - 1][0];
            } while (count($rows) === self::CHUNK);

            return $revoked;
        });
    }

    /**
     * End every live session of the identity the connection established
     * (`link_removed`), unless the trigger is turned off. Returns how many
     * sessions this call revoked; an identity that is not an Eloquent model has
     * no sessions to end.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function link(Identity $identity, string $connectionId, CarbonImmutable $now): int
    {
        if (!$this->isEnabled($connectionId, RevocationReason::LINK_REMOVED) || !$identity instanceof Model) {
            return 0;
        }

        $model = SessionLookup::model();

        return $model->getConnection()->transaction(function () use ($model, $identity, $connectionId, $now): int {

            $revoked = 0;
            $after   = null;

            do {
                $keys = self::owned($model, $identity, $after, $now);
                $revoked += $this->revoke($model, self::through($keys, $connectionId), $identity, RevocationReason::LINK_REMOVED, $now);
                $after = $keys === [] ? null : $keys[count($keys) - 1];
            } while (count($keys) === self::CHUNK);

            return $revoked;
        });
    }

    /**
     * Whether the trigger ends sessions, once the connection id names one.
     *
     * @param  string  $connectionId
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isEnabled(string $connectionId, RevocationReason $reason): bool
    {
        if ($connectionId === '') {
            throw new \InvalidArgumentException('A connection is named by its id, which may not be empty.');
        }

        return (new RevocationSettings($this->container->make(Repository::class)))->isEnabled($reason);
    }

    /**
     * The next chunk of the provenance rows of the connection, after the key
     * given, in key order, as `[session key, connection id]`, read from the
     * provenance's connection index on the write connection. The index finds
     * them under the column's collation; `exactly()` keeps those that name the
     * connection byte for byte.
     *
     * @param  string  $connectionId
     * @param  ?string  $after
     * @return list<array{0: string, 1: mixed}>
     */
    private static function established(string $connectionId, ?string $after): array
    {
        $query = WriteConnection::query(SessionProvenance::query())
            ->where('connection_id', $connectionId)
            ->when($after !== null, static fn (Builder $query): Builder => $query->where('session_id', '>', $after))
            ->orderBy('session_id')
            ->limit(self::CHUNK);

        return self::provenance($query);
    }

    /**
     * The next chunk of the keys of the identity's live sessions, after the key
     * given, in key order, read on the write connection.
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
            ->limit(self::CHUNK);

        return self::strings(WriteConnection::during($model, static fn (): array => $query->pluck($model->getKeyName())->all()));
    }

    /**
     * Those of the session keys the connection established, read from the
     * provenance on the write connection.
     *
     * @param  list<string>  $keys
     * @param  string  $connectionId
     * @return list<string>
     */
    private static function through(array $keys, string $connectionId): array
    {
        if ($keys === []) {
            return [];
        }

        $query = WriteConnection::query(SessionProvenance::query())->whereKey($keys)->where('connection_id', $connectionId);

        return self::exactly(self::provenance($query), $connectionId);
    }

    /**
     * The provenance rows the query finds, as `[session key, connection id]`,
     * read on the write connection.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\SessionProvenance>  $query
     * @return list<array{0: string, 1: mixed}>
     */
    private static function provenance(Builder $query): array
    {
        /** @var array<int, \stdClass> $rows */
        $rows  = WriteConnection::during(new SessionProvenance, static fn (): array => $query->toBase()->get(['session_id', 'connection_id'])->all());
        $pairs = [];

        foreach ($rows as $row) {

            $key = IdentifierCoercion::stringify($row->session_id);

            if ($key === null) {
                continue;
            }

            $pairs[] = [$key, $row->connection_id];
        }

        return $pairs;
    }

    /**
     * The session keys of the provenance rows that name the connection byte for
     * byte, so a column whose collation counts another connection's id as equal
     * (another case or accent, a trailing space) never ends that connection's
     * sessions.
     *
     * @param  list<array{0: string, 1: mixed}>  $rows
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

        return $keys;
    }

    /**
     * Lock the live sessions with the keys given, in key order, and revoke each
     * with the reason, reporting it once committed. Returns how many this call
     * revoked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  list<string>  $keys
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @return int
     */
    private function revoke(EloquentSession&Model $model, array $keys, ?Identity $identity, RevocationReason $reason, CarbonImmutable $now): int
    {
        if ($keys === []) {
            return 0;
        }

        $query = self::live(WriteConnection::query($model->newQuery()), $model, $now)->whereKey($keys)->orderBy($model->getKeyName())->lockForUpdate();

        /** @var list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> $sessions */
        $sessions = WriteConnection::during($model, static fn (): array => $query->get()->all());
        $revoked  = 0;

        foreach ($sessions as $session) {

            $context = new EventContext($session->getGuard(), $this->context->client(), $identity, session: $session, method: $session->getSignInMethod(), fromSession: true);
            $event   = new SessionRevoked($context, $reason);

            $revoked += $this->writer->revoke($session, $reason, $now, fn () => $this->context->dispatch($event)) ? 1 : 0;
        }

        return $revoked;
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
