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
 * Decides whether a signing-in client's refresh token proves it holds an
 * existing session, which the new session then replaces.
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
     * identity and any principal given, or `null` when it proves none.
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
     * Whether the session is the identity's live, active session of the guard
     * and holds the rotation id as its current one.
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
