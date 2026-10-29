<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;

/**
 * Writes a session the session service starts: a new device, or the existing
 * device a client proved it holds, and the first token pair.
 *
 * Each runs in one transaction on the device's connection. The device is
 * written first and the tokens are issued after it, inside the transaction, so
 * any failure while issuing (signing, randomness, an identifier that cannot be
 * read) rolls the write back and no device is left without a client that holds
 * its refresh token. Only the digest of the new rotation id is stored. Every
 * time is the one `$now` of the sign-in, formatted with the device model's own
 * date format.
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
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     */
    public function __construct(

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
     * model), the principal, the guard and sign-in method, the client's name
     * and platform, the IP address and user agent of the client the sign-in
     * came from (`$origin`) as its creation, the context's client and the
     * sign-in as its last use (so recording the use when the guard binds it
     * writes nothing more), the digest of a new rotation id, and both
     * deadlines.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $method
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
        string $guard,
        AdmittedSignIn $admitted,
        string $method,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
        ClientContext $origin,
    ): SignedInSession {
        $device     = DeviceLookup::model();
        $identity   = self::eloquentIdentity($admitted);
        $rotationId = RefreshTokenHasher::generate();
        $owner      = $device->authenticatable();

        [$principalType, $principalId] = PrincipalReference::columns($device);

        $device->forceFill([
            $owner->getMorphType()             => $identity->getMorphClass(),
            $owner->getForeignKeyName()        => IdentifierCoercion::stringify($identity->getKey()),
            $principalType                     => PrincipalReference::type($admitted->principal),
            $principalId                       => PrincipalReference::id($admitted->principal),
            $device->getGuardName()            => $guard,
            $device->getSignInMethodName()     => $method,
            $device->getClientNameName()       => $context->clientName,
            $device->getPlatformName()         => $context->platform,
            $device->getCreatedIpName()        => $origin->ip,
            $device->getCreatedUserAgentName() => $origin->userAgent,
            ...self::sessionState($device, $rotationId, $context, $lifetimes, $now),
        ]);

        return $device->getConnection()->transaction(function () use ($device, $admitted, $method, $rotationId, $now): SignedInSession {

            $device->save();

            return $this->issue($device, $admitted, $method, $rotationId, $now, true);
        });
    }

    /**
     * Continue the admitted sign-in on the device the client proved it holds,
     * and issue the new session's first pair; `null` when the device changed
     * after it was proven, so the sign-in cannot continue on it.
     *
     * A new sign-in is a new session, so the device gets a new rotation id (the
     * old one and its predecessor are forgotten, making every earlier refresh
     * token of the device a replay), both deadlines restart, and the sign-in
     * method, the client's name and platform when given, and the last use are
     * recorded. Its owner, principal, guard and creation details are kept. The
     * write is one compare-and-swap that applies only while the row still holds
     * the digest the client proved, is not revoked, and records the owner and
     * principal it was proven for; any concurrent refresh, revocation or change
     * makes it affect no row.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    public function continueOn(
        EloquentDevice&Model $device,
        AdmittedSignIn $admitted,
        string $method,
        SignInContext $context,
        TokenLifetimes $lifetimes,
        CarbonImmutable $now,
    ): ?SignedInSession {
        $rotationId = RefreshTokenHasher::generate();

        $values = array_filter([
            $device->getSignInMethodName() => $method,
            $device->getClientNameName()   => $context->clientName,
            $device->getPlatformName()     => $context->platform,
        ], static fn (?string $value): bool => $value !== null) + self::sessionState($device, $rotationId, $context, $lifetimes, $now);

        return $device->getConnection()->transaction(function () use ($device, $admitted, $method, $rotationId, $now, $values): ?SignedInSession {

            if (!$this->swap($device, $values)) {
                return null;
            }

            return $this->issue($device, $admitted, $method, $rotationId, $now, false);
        });
    }

    /**
     * The admitted identity, which must be an Eloquent model to own a device.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    private static function eloquentIdentity(AdmittedSignIn $admitted): Identity&Model
    {
        $identity = $admitted->identity;

        if (!$identity instanceof Model) {
            throw new \LogicException(sprintf('The session service can only create a device for an Eloquent identity; %s is not a model.', $identity::class));
        }

        return $identity;
    }

    /**
     * The state of a session that starts at `$now`: the client as its last use,
     * the digest of the new rotation id with no previous one, and both
     * deadlines.
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
            $device->getIdleExpiresAtName()      => $device->fromDateTime($lifetimes->idleDeadline($now, $absolute)),
            $device->getAbsoluteExpiresAtName()  => $device->fromDateTime($absolute),
        ];
    }

    /**
     * Apply the values to the proven device with one compare-and-swap on its
     * own connection: only while the row still holds the digest, owner and
     * principal it was loaded with, exactly as stored, and is not revoked. The
     * values are mirrored on the in-memory device as persisted state when the
     * swap changed the row. Returns whether it did.
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

        foreach ([$device->getRefreshKeyName(), $owner->getMorphType(), $owner->getForeignKeyName(), ...PrincipalReference::columns($device)] as $column) {
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
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $method
     * @param  string  $rotationId
     * @param  \Carbon\CarbonImmutable  $now
     * @param  bool  $created
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     */
    private function issue(
        EloquentDevice&Model $device,
        AdmittedSignIn $admitted,
        string $method,
        #[\SensitiveParameter] string $rotationId,
        CarbonImmutable $now,
        bool $created,
    ): SignedInSession {
        $tokens = new RefreshResult(
            $this->tokens->issueAccessToken($admitted->identity, $admitted->principal, $device, $now),
            $this->tokens->issueRefreshToken($device, $rotationId, $admitted->principal, $now),
        );

        return new SignedInSession($admitted->identity, $admitted->principal, $device, $tokens, $method, $created);
    }
}
