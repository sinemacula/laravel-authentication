<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Jwt\DeviceOwnership;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;

/**
 * Decides whether a client signing in proved, with its refresh token, that it
 * holds an existing session, so the sign-in continues on that device instead of
 * creating another.
 *
 * The proof is the refresh token carrying the device's current rotation id,
 * validly signed for the guard; it may have expired, since the usual case is a
 * client signing in again after its session ended. The device it names counts
 * only when, read from the write connection, it belongs to the identity signing
 * in, holds a session of this guard for the same principal, and is not revoked:
 * revocation is final, whatever the reason. A previous or older rotation id
 * proves nothing. Anything short of that is simply no proof: the sign-in
 * creates a device, and nothing fails, is revoked, or is reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DeviceProof
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
     * Return the device the refresh token proves the client holds for the
     * admitted sign-in, or `null` when it proves none.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $refreshToken
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \LogicException
     */
    public function provenDevice(string $guard, AdmittedSignIn $admitted, #[\SensitiveParameter] string $refreshToken): (EloquentDevice&Model)|null
    {
        return $this->provenDeviceOf($guard, $admitted->identity, $admitted->principal, $refreshToken);
    }

    /**
     * Return the device the refresh token proves the client holds for the
     * identity, as the principal when one is given (any principal otherwise, as
     * for a sign-in still to choose one), or `null` when it proves none.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $refreshToken
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \LogicException
     */
    public function provenDeviceOf(string $guard, Identity $identity, ?Principal $principal, #[\SensitiveParameter] string $refreshToken): (EloquentDevice&Model)|null
    {
        $claims     = $this->tokens->parseRefreshProof($refreshToken);
        $rotationId = $claims[Claims::JWT_ID->value] ?? null;

        if ($claims === null || !is_string($rotationId)) {
            return null;
        }

        $device = DeviceLookup::find($claims[Claims::DEVICE_ID->value]);

        return $device !== null && self::proves($device, $guard, $identity, $principal, $rotationId) ? $device : null;
    }

    /**
     * Whether the device is the identity's live session of the guard, for the
     * principal when one is given, and holds the rotation id as its current
     * one. The device's state is read inside `WriteConnection::during()` for
     * the device.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $rotationId
     * @return bool
     *
     * @throws \LogicException
     */
    private static function proves(EloquentDevice&Model $device, string $guard, Identity $identity, ?Principal $principal, #[\SensitiveParameter] string $rotationId): bool
    {
        if (!DeviceOwnership::isOwner($device, $identity) || ($principal !== null && !PrincipalReference::isRecordedOn($device, $principal))) {
            return false;
        }

        return WriteConnection::during($device, static fn (): bool => $device->getGuard() === $guard
            && $device->getRevokedAt()                                                    === null
            && RefreshTokenHasher::verify($rotationId, $device->getRefreshKey() ?? ''));
    }
}
