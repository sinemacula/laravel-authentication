<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\RequirementSubject;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;

/**
 * Reads the counting proofs, the first factor and the provenance of one of a
 * guard's live, active sessions of a person.
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
     * The session's counting proofs, newest first, filtered by `$since` and
     * `$kinds` and capped at `$limit`; `[]` when the session is not active.
     *
     * @param  string  $guard
     * @param  mixed  $session
     * @param  ?\Carbon\CarbonInterface  $since
     * @param  ?list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>  $kinds
     * @param  int  $limit
     * @return list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>
     *
     * @throws \InvalidArgumentException
     */
    public static function query(string $guard, mixed $session, ?CarbonInterface $since, ?array $kinds, int $limit): array
    {
        if ($limit < 1 || $limit > RequirementSubject::MAX_LIMIT) {
            throw new \InvalidArgumentException(sprintf('A session returns between 1 and %d proofs at a time.', RequirementSubject::MAX_LIMIT));
        }

        $active = self::active($guard, $session);

        return $active === null ? [] : SessionProofs::query($active[0], $since, $kinds, $limit, $active[1]);
    }

    /**
     * The session's oldest counting first-factor proof; `null` when the session
     * is not active or that proof no longer counts.
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
     * The external provenance the session records; `null` when the session is
     * not active or no provider established it.
     *
     * @param  string  $guard
     * @param  mixed  $session
     * @return ?\SineMacula\Laravel\Authentication\Proofs\Provenance
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public static function provenance(string $guard, mixed $session): ?Provenance
    {
        $active = self::active($guard, $session);

        return $active === null ? null : SessionProofs::provenance($active[0], $active[1]);
    }

    /**
     * The live, active session the key or instance names, and whether its row
     * was locked; `null` when there is none.
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
