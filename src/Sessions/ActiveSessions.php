<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Contracts\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\HasSessions;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Which sessions are live, and the listing of an identity's live sessions.
 *
 * A session is active while it is not revoked and both its idle and absolute
 * deadlines are still ahead: a deadline has passed from the second it names, as
 * on every other path. The listing reads the identity's `sessions()` relation
 * on the write connection, so it never shows a session a replica has not yet
 * seen revoked, and summarises each session without its digests.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActiveSessions
{
    /** @var int Largest page the listing returns. */
    public const int MAX_PER_PAGE = 100;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Constrain a query of the session's model to the sessions active at the
     * given time, with the columns its name accessors give.
     *
     * @param  \Illuminate\Contracts\Database\Eloquent\Builder  $query
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonInterface  $now
     * @return void
     */
    public static function constrain(Builder $query, EloquentSession&Model $session, CarbonInterface $now): void
    {
        $at = $session->fromDateTime($now);

        $query->whereNull($session->qualifyColumn($session->getRevokedAtName()))
            ->where($session->qualifyColumn($session->getIdleExpiresAtName()), '>', $at)
            ->where($session->qualifyColumn($session->getAbsoluteExpiresAtName()), '>', $at);
    }

    /**
     * One page of the identity's active sessions, of every guard, most recently
     * used first (never used last), then by key, newest first, each summarised
     * and marked when it is the current session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @param  int  $perPage
     * @param  ?int  $page
     * @return \Illuminate\Pagination\LengthAwarePaginator<int, \SineMacula\Laravel\Authentication\Sessions\SessionSummary>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function page(Identity $identity, ?Session $current, int $perPage, ?int $page): LengthAwarePaginator
    {
        if ($perPage < 1 || $perPage > self::MAX_PER_PAGE) {
            throw new \InvalidArgumentException(sprintf('Sessions are listed 1 to %d to a page; %d were asked for.', self::MAX_PER_PAGE, $perPage));
        }

        if (!$identity instanceof HasSessions) {
            throw new \LogicException(sprintf('Only identities that implement %s have sessions to list; %s does not.', HasSessions::class, $identity::class));
        }

        $now = CarbonImmutable::now();

        /** @var \Illuminate\Pagination\LengthAwarePaginator<int, \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession> $sessions */
        $sessions = WriteConnection::during($identity, static function () use ($identity, $now, $perPage, $page): LengthAwarePaginator {

            [$query, $session] = IdentitySessions::query($identity);

            self::constrain($query, $session, $now);

            $lastUsed = $session->qualifyColumn($session->getLastUsedAtName());

            return $query
                ->orderByRaw(sprintf('case when %s is null then 1 else 0 end', $session->getConnection()->getQueryGrammar()->wrap($lastUsed)))
                ->orderByDesc($lastUsed)
                ->orderByDesc($session->getQualifiedKeyName())
                ->paginate($perPage, ['*'], 'page', $page);
        });

        return $sessions->through(static fn (EloquentSession&Model $session): SessionSummary => SessionSummary::of($session, self::isCurrent($session, $current)));
    }

    /**
     * Whether the listed session is the session bound to the guard: the same
     * class with the same identifier.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @return bool
     */
    private static function isCurrent(EloquentSession&Model $session, ?Session $current): bool
    {
        return $current !== null
            && $current::class === $session::class
            && IdentifierCoercion::matches($current->getSessionIdentifier(), $session->getSessionIdentifier());
    }
}
