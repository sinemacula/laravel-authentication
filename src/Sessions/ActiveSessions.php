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
use SineMacula\Laravel\Authentication\Database\GrammarExpression;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\SessionRecords\SessionKeyShape;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Which sessions are live, the listing of an identity's live sessions, and the
 * lookup of one of them.
 *
 * A session is active while it is not pending, not revoked, and its idle
 * deadline, and its absolute deadline when it has one, are still ahead: a
 * deadline has passed from the second it names, as on every other path. The
 * listing and the lookup read the identity's `sessions()` relation on the write
 * connection, so neither shows a session a replica has not yet seen revoked,
 * and summarise each session without its digests.
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
     * given time, with the columns its name accessors give: active rather than
     * pending, not revoked, and before both deadlines.
     *
     * @param  \Illuminate\Contracts\Database\Eloquent\Builder  $query
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonInterface  $now
     * @return void
     */
    public static function constrain(Builder $query, EloquentSession&Model $session, CarbonInterface $now): void
    {
        $at = $session->fromDateTime($now);

        $absolute = $session->qualifyColumn($session->getAbsoluteExpiresAtName());

        $query->where($session->qualifyColumn($session->getStatusName()), SessionStatus::ACTIVE->value)
            ->whereNull($session->qualifyColumn($session->getRevokedAtName()))
            ->where($session->qualifyColumn($session->getIdleExpiresAtName()), '>', $at)
            ->where(static function (Builder $query) use ($absolute, $at): void {
                $query->whereNull($absolute)->orWhere($absolute, '>', $at);
            });
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
                ->orderBy(new GrammarExpression('case when %s is null then 1 else 0 end', [$lastUsed]))
                ->orderByDesc($lastUsed)
                ->orderByDesc($session->getQualifiedKeyName())
                ->paginate($perPage, ['*'], 'page', $page);
        });

        return $sessions->through(static fn (EloquentSession&Model $session): SessionSummary => SessionSummary::of($session, self::isCurrent($session, $current)));
    }

    /**
     * One of the identity's active sessions, of any guard, by its key,
     * summarised as the listing summarises it and marked when it is the current
     * session; `null` when it is not the identity's, not active, or not found.
     * A key that cannot be one of the session model's is not queried.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $id
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SessionSummary
     *
     * @throws \LogicException
     */
    public static function find(Identity $identity, mixed $id, ?Session $current): ?SessionSummary
    {
        if (!$identity instanceof HasSessions) {
            throw new \LogicException(sprintf('Only identities that implement %s have sessions to list; %s does not.', HasSessions::class, $identity::class));
        }

        [$query, $session] = IdentitySessions::query($identity);

        if (!SessionKeyShape::matches($session, $id)) {
            return null;
        }

        $now = CarbonImmutable::now();

        $found = WriteConnection::during($identity, static function () use ($query, $session, $id, $now): mixed {

            self::constrain($query, $session, $now);

            return $query->where($session->getQualifiedKeyName(), $id)->first();
        });

        return $found instanceof $session ? SessionSummary::of($found, self::isCurrent($found, $current)) : null;
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
