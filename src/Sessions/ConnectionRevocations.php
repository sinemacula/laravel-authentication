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
use SineMacula\Laravel\Authentication\Database\GrammarExpression;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Ends the sessions an external provider's connection established, or an
 * identity's sessions established through one link.
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
     * End every live session the connection established unless the trigger is
     * turned off, returning how many this call revoked.
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

            ConnectionGuards::connection($model->getConnection(), $connectionId);

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
     * End every live session of the identity established through the link
     * unless the trigger is turned off, returning how many this call revoked.
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

            ConnectionGuards::link($model->getConnection(), $connectionId, $linkId);

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
     * Refuse an empty connection or link id.
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
     * Whether the trigger ends sessions.
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
     * The next chunk of the connection's provenance rows after the key given,
     * in key order, as `[session key, connection id]`, with a locking read.
     *
     * Integer keys, held as strings, sort by length and then as strings.
     *
     * @param  string  $connectionId
     * @param  ?string  $after
     * @param  bool  $numeric
     * @return list<array{0: mixed, 1: mixed}>
     */
    private static function established(string $connectionId, ?string $after, bool $numeric): array
    {
        $query = WriteConnection::query(SessionProvenance::query());

        $query->where('connection_id', $connectionId)
            ->when($after !== null && $numeric, static fn (Builder $query): Builder => self::numericallyAfter($query, (string) $after))
            ->when($after !== null && !$numeric, static fn (Builder $query): Builder => $query->where('session_id', '>', $after))
            ->when($numeric, static fn (Builder $query): Builder => $query->orderBy(new GrammarExpression('length(%s)', ['session_id'])))
            ->orderBy('session_id')
            ->limit(self::CHUNK)
            ->sharedLock();

        return self::provenance($query);
    }

    /**
     * Hold the query to the provenance of integer keys numerically after the
     * key given.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\SessionProvenance>  $query
     * @param  string  $after
     * @return \Illuminate\Database\Eloquent\Builder<\SineMacula\Laravel\Authentication\Models\SessionProvenance>
     */
    private static function numericallyAfter(Builder $query, string $after): Builder
    {
        return $query->where(static function (Builder $query) use ($after): void {
            $query->whereRaw(new GrammarExpression('length(%s) > ?', ['session_id']), [strlen($after)])
                ->orWhere(static function (Builder $query) use ($after): void {
                    $query->whereRaw(new GrammarExpression('length(%s) = ?', ['session_id']), [strlen($after)])->where('session_id', '>', $after);
                });
        });
    }

    /**
     * The next chunk of the keys of the identity's live external sessions after
     * the key given, in key order, locked until the transaction ends.
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
            ->where($model->getSignInMethodName(), SignInMethodManager::EXTERNAL_METHOD)
            ->when($after !== null, static fn (Builder $query): Builder => $query->where($model->getKeyName(), '>', $after))
            ->orderBy($model->getKeyName())
            ->limit(self::CHUNK)
            ->lockForUpdate();

        return self::strings(WriteConnection::during($model, static fn (): array => $query->pluck($model->getKeyName())->all()));
    }

    /**
     * Those of the session keys whose provenance records the link byte for
     * byte, read with a locking read.
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
     * The provenance rows the query finds, as `[session key, connection id]`.
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
     * The session keys, as strings, of the provenance rows that name the
     * connection byte for byte, whatever the column's collation.
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
     * Forget the guard's binding to any revoked session once the revocation
     * commits, before any is reported, answering the list they are added to.
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
     * Lock the live sessions with the keys given, in key order, and revoke
     * each, returning how many this call revoked.
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
     * Hold the query to unrevoked sessions before both deadlines, whatever
     * their status.
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
