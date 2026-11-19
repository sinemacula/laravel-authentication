<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Revokes sessions for the session service: one session, or every session of
 * one or more scopes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RevocationWriter
{
    /** @var int Sessions read per chunk of a bulk revocation. */
    public const int CHUNK = 500;

    /** @var \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore The conditional revocation write. */
    private RefreshRotationStore $store;

    /** @var \SineMacula\Laravel\Authentication\Database\AfterCommit Defers the reports until the revocations commit. */
    private AfterCommit $afterCommit;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     */
    public function __construct(ConnectionResolverInterface $connections, \Closure $transactions)
    {
        $this->store       = new RefreshRotationStore($connections);
        $this->afterCommit = new AfterCommit($transactions);
    }

    /**
     * Revoke the session unless it is already revoked, and run the report once
     * the revocation commits; whether this call revoked it.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(): void  $report
     * @return bool
     *
     * @imperative
     */
    public function revoke(EloquentSession&Model $session, RevocationReason $reason, CarbonImmutable $now, \Closure $report): bool
    {
        $revoked = $this->store->revoke($session, $reason, $now);

        if ($revoked) {
            $this->afterCommit->run($session, $report);
        }

        return $revoked;
    }

    /**
     * End every session of the scopes except the given one, and return how many
     * this call revoked.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \SineMacula\Laravel\Authentication\Sessions\RevocationScope): void  $sessionRevoked
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\RevocationScope, int, ?\Carbon\CarbonImmutable): void  $scopeEnded
     * @param  ?\Closure(): void  $committed
     * @return int
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function revokeScopes(
        array $scopes,
        RevocationReason $reason,
        ?Session $except,
        CarbonImmutable $now,
        \Closure $sessionRevoked,
        \Closure $scopeEnded,
        ?\Closure $committed = null,
    ): int {
        $moved  = array_map(static fn (RevocationScope $scope): ?HasTokensValidAfter => self::moveCutoff($scope, $now), $scopes);
        $anchor = SessionLookup::model();

        $this->keep($moved, $except, $now);

        return $anchor->getConnection()->transaction(function () use ($scopes, $moved, $reason, $except, $now, $sessionRevoked, $scopeEnded, $committed, $anchor): int {

            if ($committed !== null) {
                $this->afterCommit->run($anchor, $committed);
            }

            $revoked = $this->revokeInKeyOrder($scopes, $reason, $except, $now);
            $total   = 0;

            foreach ($scopes as $index => $scope) {

                self::forgetChanges($scope);

                foreach ($revoked[$index] as $session) {
                    $this->afterCommit->run($session, static fn () => $sessionRevoked($session, $scope));
                }

                $count  = count($revoked[$index]);
                $cutoff = $moved[$index] === null ? null : $now;

                $this->afterCommit->run($anchor, static function () use ($scopeEnded, $scope, $count, $cutoff): void {
                    $scopeEnded($scope, $count, $cutoff);
                });

                $total += $count;
            }

            return $total;
        });
    }

    /**
     * End every session of the scopes once more after the open transactions
     * commit, since the first pass may have read them through an earlier
     * snapshot.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Contracts\Principal|\SineMacula\Laravel\Authentication\Contracts\Tenant  $changed
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \SineMacula\Laravel\Authentication\Sessions\RevocationScope): void  $sessionRevoked
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function revokeAgain(array $scopes, RevocationReason $reason, Identity|Principal|Tenant $changed, \Closure $sessionRevoked): void
    {
        $models = $changed instanceof Model ? [SessionLookup::model(), $changed] : [SessionLookup::model()];

        if (array_filter($models, $this->afterCommit->defers(...)) === []) {
            return;
        }

        $kept = array_map(static fn (RevocationScope $scope): RevocationScope => $scope->keepingCutoff(), $scopes);

        $this->afterCommit->runAcross($models, function () use ($kept, $reason, $sessionRevoked): void {
            $this->revokeScopes($kept, $reason, null, CarbonImmutable::now()->startOfSecond(), $sessionRevoked, static fn () => null);
        });
    }

    /**
     * Revoke the scopes' unrevoked sessions but the excepted one in one key
     * order across the scopes, a chunk at a time, and return the sessions each
     * scope revoked.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  \Carbon\CarbonImmutable  $now
     * @return non-empty-list<list<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function revokeInKeyOrder(array $scopes, RevocationReason $reason, ?Session $except, CarbonImmutable $now): array
    {
        $revoked = array_fill(0, count($scopes), []);
        $found   = array_filter(array_map(static fn (RevocationScope $scope): ?array => $scope->sessions, $scopes));
        $last    = array_key_last($found);

        if ($last === null) {
            return $revoked;
        }

        [$sessions, $model] = $found[$last];

        $owners = array_intersect_key($scopes, $found);
        $query  = self::unrevoked(count($found) === 1 ? $sessions : self::union($model, array_column($found, 0)), $model, $except);

        WriteConnection::during($model, function () use ($query, $owners, $last, $reason, $now, &$revoked): void {

            /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $session */
            foreach ($query->lazyById(self::CHUNK) as $session) {

                if (!$this->store->revoke($session, $reason, $now)) {
                    continue;
                }

                $revoked[self::scopeOf($owners, $session, $last)][] = $session;
            }
        });

        return $revoked;
    }

    /**
     * The index of the first principal's scope the session records, otherwise
     * the last scope's.
     *
     * @param  array<int, \SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  int  $last
     * @return int
     */
    private static function scopeOf(array $scopes, EloquentSession&Model $session, int $last): int
    {
        foreach ($scopes as $index => $scope) {
            if ($scope->principal !== null && PrincipalReference::isRecordedOn($session, $scope->principal)) {
                return $index;
            }
        }

        return $last;
    }

    /**
     * A query of the sessions any of the queries finds.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  list<\Illuminate\Contracts\Database\Eloquent\Builder>  $queries
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    private static function union(EloquentSession&Model $model, array $queries): Builder
    {
        return WriteConnection::query($model->newQuery())->where(static function (EloquentBuilder $union) use ($queries): void {
            foreach ($queries as $query) {
                $union->orWhere(static fn (EloquentBuilder $nested): EloquentBuilder => $nested->addNestedWhereQuery($query->toBase()));
            }
        });
    }

    /**
     * The query's unrevoked sessions but the excepted one.
     *
     * @param  \Illuminate\Contracts\Database\Eloquent\Builder  $sessions
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    private static function unrevoked(Builder $sessions, EloquentSession&Model $model, ?Session $except): Builder
    {
        $query = (clone $sessions)->whereNull($model->qualifyColumn($model->getRevokedAtName()));

        if ($except instanceof $model) {
            $query->whereKeyNot($except->getSessionIdentifier());
        }

        return $query;
    }

    /**
     * Move the scope's "tokens valid after" cutoff to the time given, and
     * return its holder when this moved it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationScope  $scope
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter
     */
    private static function moveCutoff(RevocationScope $scope, CarbonImmutable $now): ?HasTokensValidAfter
    {
        return $scope->cutoff?->invalidateTokensIssuedBefore($now) === true ? $scope->cutoff : null;
    }

    /**
     * Record the excepted session as kept by each holder whose cutoff this call
     * moved, until that move rolls back.
     *
     * @param  list<?\SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter>  $moved
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private function keep(array $moved, ?Session $except, CarbonImmutable $now): void
    {
        if (!$except instanceof Model) {
            return;
        }

        $kept = Container::getInstance()->make(KeptSessions::class);

        foreach (array_filter($moved) as $holder) {

            $forget = $kept->keep($except, $holder, $now);

            if (!$holder instanceof Model) {
                continue;
            }

            $this->afterCommit->runIfRolledBack($holder, $forget);
        }
    }

    /**
     * Delete the scope's pending identifier changes, whatever guard requested
     * them, in one statement.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationScope  $scope
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function forgetChanges(RevocationScope $scope): void
    {
        if ($scope->changes === []) {
            return;
        }

        PendingChanges::forget($scope->changes);
    }
}
