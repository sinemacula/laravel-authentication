<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Devices\DeviceLookup;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Writes a session the session service starts: always a new device, which
 * replaces the existing device a client proved it holds, if any, and the first
 * token pair.
 *
 * Each runs in one transaction on the device's connection. The device is
 * written first (after the revocation of the device it replaces) and the tokens
 * are issued after it, inside the transaction, so any failure while issuing
 * (signing, randomness, an identifier that cannot be read) rolls every write
 * back: no device is left without a client that holds its refresh token, and no
 * device is revoked for a replacement that was not written. Only the digest of
 * the new rotation id is stored. Every time is the one `$now` of the sign-in,
 * formatted with the device model's own date format.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionWriter
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(

        /** Name of the guard whose sessions the writer writes. */
        private string $guard,

        /** The guard's token service, which issues the pair. */
        private JwtTokenService $tokens,

        /** Resolver for the device's own connection. */
        private ConnectionResolverInterface $connections,
    ) {}

    /**
     * Create a device of the configured model for the admitted sign-in and
     * issue its first pair.
     *
     * The device records its owner (the identity, which must be an Eloquent
     * model), the principal, the guard, the sign-in method and the type of
     * identifier it used, the client's name and platform, the IP address and
     * user agent of the client the sign-in came from (`$origin`) as its
     * creation, the context's client and the sign-in as its last use (so
     * recording the use when the guard binds it writes nothing more), the
     * digest of a new rotation id, and both deadlines.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function create(
        Admitted $admitted,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ClientContext $origin,
    ): SignedInSession {
        $rotationId = RefreshTokenHasher::generate();
        $device     = $this->newDevice($admitted, $method, $identifierType, $context, $origin);

        $device->forceFill(self::sessionState($device, $rotationId, $context, $lifetimes, $now));

        return $device->getConnection()->transaction(function () use ($device, $admitted, $method, $rotationId, $now): SignedInSession {

            $device->save();

            return $this->issue($device, $admitted, $method, $rotationId, $now);
        });
    }

    /**
     * Replace the device the client proved it holds, the admitted sign-in's
     * device, with a new one for the sign-in, and issue the new device's first
     * pair; `null` when the proven device changed after it was proven, so it
     * cannot be replaced.
     *
     * Every sign-in is a new session, so the new device is written exactly as
     * `create()` writes one, except that a client name or platform the context
     * does not give is the proven device's (the client proved it is the same
     * one). The proven device is revoked first, with the reason `superseded`
     * and both of its digests forgotten, by one compare-and-swap that applies
     * only while the row still holds the digest the client proved, is not
     * revoked, and records the owner, principal and guard it was proven for;
     * any concurrent refresh, revocation or change makes it affect no row, and
     * then nothing is written. The revocation, the new device and its pair are
     * one transaction, so a failure while issuing leaves the proven device as
     * it was.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function replace(
        Admitted $admitted,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ClientContext $origin,
    ): ?SignedInSession {
        $previous   = self::provenDevice($admitted);
        $rotationId = RefreshTokenHasher::generate();
        $described  = new SignInContext(
            $context->client,
            $context->clientName ?? self::recorded($previous, $previous->getClientNameName()),
            $context->platform   ?? self::recorded($previous, $previous->getPlatformName()),
        );
        $device = $this->newDevice($admitted, $method, $identifierType, $described, $origin);

        $device->forceFill(self::sessionState($device, $rotationId, $described, $lifetimes, $now));

        $revoked = [
            $previous->getRevokedAtName()          => $previous->fromDateTime($now),
            $previous->getRevokedReasonName()      => RevocationReason::SUPERSEDED->value,
            $previous->getRefreshKeyName()         => null,
            $previous->getPreviousRefreshKeyName() => null,
        ];

        return $device->getConnection()->transaction(function () use ($previous, $revoked, $device, $admitted, $method, $rotationId, $now): ?SignedInSession {

            if (!$this->swap($previous, $revoked)) {
                return null;
            }

            $device->save();

            return $this->issue($device, $admitted, $method, $rotationId, $now);
        });
    }

    /**
     * A new, unsaved device of the configured model for the admitted sign-in,
     * created from the origin's client, with the context's client name and
     * platform, and no session yet.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function newDevice(Admitted $admitted, string $method, ?string $identifierType, SignInContext $context, ClientContext $origin): EloquentDevice&Model
    {
        $device   = DeviceLookup::model();
        $identity = self::eloquentIdentity($admitted);
        $owner    = $device->authenticatable();

        [$principalType, $principalId] = PrincipalReference::columns($device);

        return $device->forceFill([
            $owner->getMorphType()                 => $identity->getMorphClass(),
            $owner->getForeignKeyName()            => IdentifierCoercion::stringify($identity->getKey()),
            $principalType                         => PrincipalReference::type($admitted->principal),
            $principalId                           => PrincipalReference::id($admitted->principal),
            $device->getGuardName()                => $this->guard,
            $device->getSignInMethodName()         => $method,
            $device->getSignInIdentifierTypeName() => $identifierType,
            $device->getClientNameName()           => $context->clientName,
            $device->getPlatformName()             => $context->platform,
            $device->getCreatedIpName()            => $origin->ip,
            $device->getCreatedUserAgentName()     => $origin->userAgent,
        ]);
    }

    /**
     * The device the admitted sign-in is on, which the client proved it holds
     * and which must be an Eloquent device to be replaced.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice
     *
     * @throws \LogicException
     */
    private static function provenDevice(Admitted $admitted): EloquentDevice&Model
    {
        $device = $admitted->device;

        if (!$device instanceof EloquentDevice || !$device instanceof Model) {
            throw new \LogicException('The session service can only replace an Eloquent device the client proved it holds.');
        }

        return $device;
    }

    /**
     * A description the device recorded, as loaded: its text, or `null` when it
     * recorded none.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $device
     * @param  string  $column
     * @return ?string
     */
    private static function recorded(Model $device, string $column): ?string
    {
        $value = $device->getRawOriginal($column);

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * The admitted identity, which must be an Eloquent model to own a device.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    private static function eloquentIdentity(Admitted $admitted): Identity&Model
    {
        $identity = $admitted->identity;

        if (!$identity instanceof Model) {
            throw new \LogicException(sprintf('The session service can only create a device for an Eloquent identity; %s is not a model.', $identity::class));
        }

        return $identity;
    }

    /**
     * The state of a session that starts at `$now`: the client as its last use,
     * the digest of the new rotation id with no previous one, the start itself,
     * and both deadlines.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  string  $rotationId
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @return array<string, mixed>
     */
    private static function sessionState(
        EloquentDevice&Model $device,
        #[\SensitiveParameter] string $rotationId,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
    ): array {
        $absolute = $lifetimes->absoluteDeadline($now);

        return [
            $device->getLastUsedAtName()         => $device->fromDateTime($now),
            $device->getLastUsedIpName()         => $context->client->ip,
            $device->getLastUsedUserAgentName()  => $context->client->userAgent,
            $device->getRefreshKeyName()         => RefreshTokenHasher::hash($rotationId),
            $device->getPreviousRefreshKeyName() => null,
            $device->getRefreshRotatedAtName()   => null,
            $device->getSignedInAtName()         => $device->fromDateTime($now),
            $device->getIdleExpiresAtName()      => $device->fromDateTime($lifetimes->idleDeadline($now, $absolute)),
            $device->getAbsoluteExpiresAtName()  => $device->fromDateTime($absolute),
        ];
    }

    /**
     * Apply the values to the proven device with one compare-and-swap on its
     * own connection: only while the row still holds the digest, owner,
     * principal and guard it was loaded with, exactly as stored, and is not
     * revoked. The values are mirrored on the in-memory device as persisted
     * state when the swap changed the row. Returns whether it did.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  array<string, mixed>  $values
     * @return bool
     *
     * @imperative
     */
    private function swap(EloquentDevice&Model $device, array $values): bool
    {
        $owner  = $device->authenticatable();
        $proven = [];

        foreach ([$device->getRefreshKeyName(), $owner->getMorphType(), $owner->getForeignKeyName(), ...PrincipalReference::columns($device), $device->getGuardName()] as $column) {
            $proven[$column] = $device->getRawOriginal($column);
        }

        $affected = $this->connections
            ->connection($device->getConnectionName())
            ->table($device->getTable())
            ->where($device->getKeyName(), $device->getKey())
            ->where($proven)
            ->whereNull($device->getRevokedAtName())
            ->update($values);

        if ($affected !== 1) {
            return false;
        }

        $device->forceFill($values)->syncOriginalAttributes(array_keys($values));

        return true;
    }

    /**
     * Issue the session's first pair at `$now`, after the device was written.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  string  $method
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function issue(EloquentDevice&Model $device, Admitted $admitted, string $method, #[\SensitiveParameter] string $rotationId, CarbonImmutable $now): SignedInSession
    {
        $tokens = new TokenPair(
            $this->tokens->issueAccessToken($admitted->identity, $admitted->principal, $device, $now),
            $this->tokens->issueRefreshToken($device, $rotationId, $admitted->principal, $now),
        );

        return new SignedInSession($admitted->identity, $admitted->principal, $device, $tokens, $method);
    }
}
