<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;

/**
 * Revokes sessions for the session service: one session, or every session of
 * one or more scopes (an identity's, or a principal's).
 *
 * Each session is revoked by its own conditional `UPDATE` (only while it is not
 * revoked yet), so revoking is idempotent, the first revocation's time and
 * reason are kept, and of two calls racing for a session only the one that
 * changed the row reports it. Reports run once the revocation commits on the
 * session's own connection, never for one rolled back.
 *
 * A bulk revocation first moves each scope's "tokens valid after" cutoff to
 * `$now` on the scope's own connection, then, in one transaction on the session
 * model's connection, revokes every unrevoked session of each scope, pending
 * sessions included (so a pending credential issued before cannot activate a
 * session afterwards), read on the write connection in key order in chunks of
 * 500, and deletes the pending identifier changes of an identity's scope (also
 * kept on that connection), so a change link requested from a session that
 * ends, which needs no session to confirm, cannot move the account afterwards.
 * A failure in the transaction leaves the cutoffs moved: more is cut off, never
 * less, and a retry is idempotent.
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
     * the revocation commits. Returns whether this call revoked it.
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
     * End every session of the scopes, except the given session, and return how
     * many sessions this call revoked. Once the transaction commits, the
     * `$committed` callback given runs first, then each revoked session is
     * reported, then each scope with its count and the cutoff this call set for
     * it.
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
        $cutoffs = array_map(static fn (RevocationScope $scope): ?CarbonImmutable => $scope->cutoff?->invalidateTokensIssuedBefore($now) === true ? $now : null, $scopes);
        $anchor  = SessionLookup::model();

        return $anchor->getConnection()->transaction(function () use ($scopes, $cutoffs, $reason, $except, $now, $sessionRevoked, $scopeEnded, $committed, $anchor): int {

            if ($committed !== null) {
                $this->afterCommit->run($anchor, $committed);
            }

            $total = 0;

            foreach ($scopes as $index => $scope) {

                $revoked = $this->revokeSessionsOf($scope, $reason, $except, $now, $sessionRevoked);

                self::forgetChanges($scope);

                $cutoff = $cutoffs[$index];

                $this->afterCommit->run($anchor, static function () use ($scopeEnded, $scope, $revoked, $cutoff): void {
                    $scopeEnded($scope, $revoked, $cutoff);
                });

                $total += $revoked;
            }

            return $total;
        });
    }

    /**
     * End every session of the scopes once more, for a deactivation or deletion
     * of the model given, once the transactions open now on the session model's
     * connection and on the model's own have committed, in turn: the
     * transaction the scopes were first ended in may have read the sessions
     * through a snapshot taken before a sign-in, a choice or a switch that
     * admitted the model committed one, which a read after the change's commit
     * finds. Every cutoff stays where the first pass left it, each session this
     * pass revokes is reported, and no scope is. With no transaction open on
     * either connection, the first pass already read past every commit and
     * nothing is done; a rollback runs nothing.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  object  $changed
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \SineMacula\Laravel\Authentication\Sessions\RevocationScope): void  $sessionRevoked
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function revokeAgain(array $scopes, RevocationReason $reason, object $changed, \Closure $sessionRevoked): void
    {
        $models = $changed instanceof Model ? [SessionLookup::model(), $changed] : [SessionLookup::model()];

        if (array_filter($models, $this->afterCommit->defers(...)) === []) {
            return;
        }

        $kept = array_map(static fn (RevocationScope $scope): RevocationScope => $scope->keepingCutoff(), $scopes);

        $this->afterCommit->runAcross($models, fn () => $this->revokeScopes($kept, $reason, null, CarbonImmutable::now()->startOfSecond(), $sessionRevoked, static fn () => null));
    }

    /**
     * Revoke every unrevoked session of the scope but the excepted one, reading
     * them on the write connection in key order, a chunk at a time, and queue
     * each revoked session's report. The scope's query is copied, never
     * narrowed, so a scope can be ended again (`revokeAgain()`).
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationScope  $scope
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \Closure(\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, \SineMacula\Laravel\Authentication\Sessions\RevocationScope): void  $sessionRevoked
     * @return int
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function revokeSessionsOf(RevocationScope $scope, RevocationReason $reason, ?Session $except, CarbonImmutable $now, \Closure $sessionRevoked): int
    {
        if ($scope->sessions === null) {
            return 0;
        }

        [$sessions, $model] = $scope->sessions;

        $query = (clone $sessions)->whereNull($model->qualifyColumn($model->getRevokedAtName()));

        if ($except instanceof $model) {
            $query->whereKeyNot($except->getSessionIdentifier());
        }

        return WriteConnection::during($model, function () use ($query, $reason, $now, $sessionRevoked, $scope): int {

            $revoked = 0;

            /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession $session */
            foreach ($query->lazyById(self::CHUNK) as $session) {

                if (!$this->revoke($session, $reason, $now, static fn () => $sessionRevoked($session, $scope))) {
                    continue;
                }

                $revoked++;
            }

            return $revoked;
        });
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
