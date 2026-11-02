<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Decides whether a client signing in proved, with its refresh token, that it
 * holds an existing session, so the new session the sign-in creates replaces
 * that session, which is revoked (`superseded`).
 *
 * The proof is the refresh token carrying the session's current rotation id,
 * validly signed for the guard; it may have expired, since the usual case is a
 * client signing in again after its session ended. The session it names counts
 * only when, read from the write connection, it belongs to the identity signing
 * in, is of this guard for the same principal, is not revoked (revocation is
 * final, whatever the reason) and is active: a session that returned to pending
 * keeps its refresh digest, but proves nothing until it activates again. A
 * previous or older rotation id proves nothing. Anything short of that is
 * simply no proof: the sign-in creates a session, and nothing fails, is
 * revoked, or is reported. The IP address, user agent, client name and platform
 * never count.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvenSessions
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     */
    public function __construct(

        /** The guard's token service, which verifies the refresh token. */
        private JwtTokenService $tokens,
    ) {}

    /**
     * Return the session the refresh token proves the client holds for the
     * admitted sign-in, or `null` when it proves none.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \LogicException
     */
    public function provenSession(string $guard, Admitted $admitted, #[\SensitiveParameter] Secret|string $refreshToken): (EloquentSession&Model)|null
    {
        return $this->provenSessionOf($guard, $admitted->identity, $admitted->principal, $refreshToken);
    }

    /**
     * Return the session the refresh token proves the client holds for the
     * identity, as the principal when one is given (any principal otherwise, as
     * for a sign-in still to choose one), or `null` when it proves none.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \LogicException
     */
    public function provenSessionOf(string $guard, Identity $identity, ?Principal $principal, #[\SensitiveParameter] Secret|string $refreshToken): (EloquentSession&Model)|null
    {
        $claims     = $this->tokens->parseRefreshProof($refreshToken);
        $rotationId = $claims[Claims::JWT_ID->value] ?? null;

        if ($claims === null || !is_string($rotationId)) {
            return null;
        }

        $session = SessionLookup::find($claims[Claims::SESSION_ID->value]);

        return $session !== null && self::proves($session, $guard, $identity, $principal, $rotationId) ? $session : null;
    }

    /**
     * Whether the session is the identity's live, active session of the guard,
     * for the principal when one is given, and holds the rotation id as its
     * current one. The session's state is read inside
     * `WriteConnection::during()` for the session.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $rotationId
     * @return bool
     *
     * @throws \LogicException
     */
    private static function proves(EloquentSession&Model $session, string $guard, Identity $identity, ?Principal $principal, #[\SensitiveParameter] string $rotationId): bool
    {
        if (!SessionOwnership::isOwner($session, $identity) || ($principal !== null && !PrincipalReference::isRecordedOn($session, $principal))) {
            return false;
        }

        return WriteConnection::during($session, static fn (): bool => $session->getGuard() === $guard
            && $session->getRevokedAt()                                                     === null
            && $session->getStatus()                                                        === SessionStatus::ACTIVE
            && RefreshTokenHasher::verify($rotationId, $session->getRefreshKey() ?? ''));
    }
}
