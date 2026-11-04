<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;

/**
 * Reads the counting proofs and the first factor of one of a guard's live,
 * active sessions of a person, for the session service's public reads and a
 * contribution subject's.
 *
 * The session is named by its key (whichever session holds it now) or given as
 * a `Session` (only while its key still holds that very session: the same
 * generation and owner). Its row is read on the write connection, and answers
 * nothing, without saying why, when the key cannot be one of the session
 * model's (no query), names no row, or names a session of another guard (or of
 * none), a revoked, pending or ended one (past its idle or absolute deadline at
 * this second, or without deadlines), or a machine's. The proofs are then read
 * bound to the row as stored (`SessionProofs`), so only its own counting proofs
 * are returned.
 *
 * Outside a transaction on the session model's connection the row and the
 * proofs are two plain reads and nothing is locked. Inside one the row is
 * locked until the transaction ends (as every other path locks a session row,
 * before its proofs) and the proofs are read current, so a step-up committed
 * before the read is returned and a proof voided before it never is, whatever
 * the transaction read first; at PostgreSQL's REPEATABLE READ the row's lock
 * fails to serialise instead when the session was written after the snapshot.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ActiveSessionProofs
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The session's counting proofs, newest first by time and then by id, only
     * those made at or after `$since` when it is given and of the given kinds
     * when they are, at most `$limit` of them (1 to
     * `RequirementSubject::MAX_LIMIT`, checked before anything is read): one
     * bounded read once the session is found live and active; `[]` when it is
     * not.
     *
     * @param  string  $guard
     * @param  mixed  $session
     * @param  ?\Carbon\CarbonImmutable  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     */
    public static function query(string $guard, mixed $session, ?CarbonImmutable $since, ?array $kinds, int $limit): array
    {
        if ($limit < 1 || $limit > RequirementSubject::MAX_LIMIT) {
            throw new \InvalidArgumentException(sprintf('A session returns between 1 and %d proofs at a time.', RequirementSubject::MAX_LIMIT));
        }

        $active = self::active($guard, $session);

        return $active === null ? [] : SessionProofs::query($active[0], $since, $kinds, $limit, $active[1]);
    }

    /**
     * The first factor the session signed in with, its oldest counting
     * first-factor proof, once the session is found live and active; `null`
     * when it is not, or when that proof no longer counts.
     *
     * @param  string  $guard
     * @param  mixed  $session
     * @return ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function firstFactor(string $guard, mixed $session): ?RecordedProof
    {
        $active = self::active($guard, $session);

        return $active === null ? null : SessionProofs::firstFactor($active[0], $active[1]);
    }

    /**
     * The stored session the key or instance names, when it is one of the
     * guard's live, active sessions of a person, and whether its row was locked
     * (inside a transaction on the session model's connection); `null` when it
     * is not. A `Session` that is not an Eloquent session names none, and is
     * not looked up.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $guard
     * @param  mixed  $session
     * @return array{0: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession, 1: bool}|null
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private static function active(string $guard, mixed $session): ?array
    {
        if ($session instanceof Session && (!$session instanceof EloquentSession || !$session instanceof Model)) {
            return null;
        }

        $key    = $session instanceof Session ? $session->getSessionIdentifier() : $session;
        $locks  = SessionLookup::model()->getConnection()->transactionLevel() > 0;
        $stored = $locks ? SessionLookup::lock($key) : SessionLookup::find($key);

        return match (true) {
            $stored === null                                                                         => null,
            $session instanceof Session && !SessionOwnership::isSameSession($session, $stored)       => null,
            OwnedSession::refusal($stored, $guard, CarbonImmutable::now()->startOfSecond()) !== null => null,
            SessionOwnership::isMachineOwned($stored)                                                => null,
            default                                                                                  => [$stored, $locks],
        };
    }
}
