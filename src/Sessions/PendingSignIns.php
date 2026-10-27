<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Guards\ActivationPolicy;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Jwt\DeviceOwnership;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;

/**
 * Issues, finds and consumes the pending sign-ins of a guard: sign-ins the
 * additional-factor policy asked a further factor of.
 *
 * A pending sign-in is completed with a token `<id>.<secret>`: the row's UUID
 * and 32 random bytes, of which only the SHA-256 digest is stored and which is
 * compared in constant time. The token works once, until the configured
 * lifetime (`authentication.sign_in.pending_ttl_seconds`, 30 to 3600 seconds,
 * 300 by default) ends, for the guard that issued it. Every read is from the
 * write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingSignIns
{
    /** @var string Configuration key of the pending credential's lifetime. */
    private const string TTL_KEY = 'authentication.sign_in.pending_ttl_seconds';

    /** @var int Lifetime used when the configuration has none, in seconds. */
    private const int DEFAULT_TTL_SECONDS = 300;

    /** @var int Shortest lifetime accepted, in seconds. */
    private const int MIN_TTL_SECONDS = 30;

    /** @var int Longest lifetime accepted, in seconds. */
    private const int MAX_TTL_SECONDS = 3600;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** Configuration the lifetime is read from on every issue. */
        private Repository $config,
    ) {}

    /**
     * Store a pending sign-in for the admitted sign-in, recording the device
     * the client proved it holds and the digest it was proven against, and
     * return its credential.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\PendingFactor
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function issue(string $guard, AdmittedSignIn $admitted, string $method, ?string $identifierType, SignInContext $context, CarbonImmutable $now): PendingFactor
    {
        $identity  = self::eloquentIdentity($admitted);
        $device    = $admitted->device;
        $secret    = RefreshTokenHasher::generate();
        $expiresAt = $now->addSeconds($this->ttlSeconds());
        $pending   = new PendingSignIn;

        $pending->forceFill([
            'id'                   => Str::uuid7()->toString(),
            'token_digest'         => RefreshTokenHasher::hash($secret),
            'purpose'              => PendingSignIn::ADDITIONAL_FACTOR,
            'guard'                => $guard,
            'sign_in_method'       => $method,
            'identifier_type'      => $identifierType,
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()),
            'principal_type'       => PrincipalReference::type($admitted->principal),
            'principal_id'         => PrincipalReference::id($admitted->principal),
            'client_name'          => $context->clientName,
            'platform'             => $context->platform,
            'created_ip'           => $context->client->ip,
            'created_user_agent'   => $context->client->userAgent,
            'device_id'            => $device === null ? null : IdentifierCoercion::stringify($device->getDeviceIdentifier()),
            'device_refresh_key'   => $device?->getRefreshKey(),
            'expires_at'           => $expiresAt,
        ])->save();

        $token = $pending->id . '.' . $secret;

        return new PendingFactor($token, $guard, $identity, $admitted->principal, $admitted->tenant, $method, $expiresAt, $device);
    }

    /**
     * Find the live pending sign-in of the guard the token completes, with its
     * identity reloaded through the guard's provider (the very owner it
     * recorded), its principal resolved again through the hinted path (the one
     * it recorded, still the identity's), and its proven device when that is
     * still the identity's live session of the guard for the principal, at the
     * digest it was proven against. Returns `null` for any token that does not
     * name such a sign-in, without saying why; a token that cannot be one (no
     * UUID, or no secret) is rejected without a query.
     *
     * @param  string  $guard
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function find(string $guard, #[\SensitiveParameter] string $token, IdentityProvider $provider, PrincipalResolver $resolver, CarbonImmutable $now): ?FoundPendingSignIn
    {
        $parts  = explode('.', $token, 2);
        $secret = $parts[1] ?? '';

        $pending = $secret !== '' && Str::isUuid($parts[0]) ? self::load($parts[0]) : null;

        if ($pending === null || !self::isLive($pending, $guard, $secret, $now)) {
            return null;
        }

        $identity  = self::owner($pending, $provider);
        $principal = $identity === null ? null : self::principal($pending, $identity, $resolver);

        return $identity === null || $principal === null ? null : self::found($pending, $secret, $token, $identity, $principal);
    }

    /**
     * Use the pending sign-in up: delete it while it still holds the digest and
     * has not expired. Returns whether this call deleted it, which only one
     * completion can.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn  $found
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     *
     * @imperative
     */
    public function consume(FoundPendingSignIn $found, CarbonImmutable $now): bool
    {
        $pending = $found->pending;

        return $pending->newQueryWithoutScopes()
            ->toBase()
            ->where($pending->getKeyName(), $pending->getKey())
            ->where('token_digest', RefreshTokenHasher::hash($found->secret))
            ->where('expires_at', '>', $pending->fromDateTime($now))
            ->delete() === 1;
    }

    /**
     * The context of the sign-in the pending one recorded: the client it came
     * from and the description it gave.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    public static function context(PendingSignIn $pending): SignInContext
    {
        return new SignInContext(new ClientContext($pending->created_ip, $pending->created_user_agent), $pending->client_name, $pending->platform);
    }

    /**
     * The admitted identity, which must be an Eloquent model to wait for a
     * factor.
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
            throw new \LogicException(sprintf('A sign-in can only wait for a further factor for an Eloquent identity; %s is not a model.', $identity::class));
        }

        return $identity;
    }

    /**
     * The configured lifetime of a pending credential, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function ttlSeconds(): int
    {
        $ttl = $this->config->get(self::TTL_KEY, self::DEFAULT_TTL_SECONDS);

        if (is_string($ttl) && preg_match('/^[1-9][0-9]{0,5}$/D', $ttl) === 1) {
            $ttl = (int) $ttl;
        }

        if (!is_int($ttl) || $ttl < self::MIN_TTL_SECONDS || $ttl > self::MAX_TTL_SECONDS) {
            throw new \InvalidArgumentException(sprintf('%s must be an integer from %d to %d seconds.', self::TTL_KEY, self::MIN_TTL_SECONDS, self::MAX_TTL_SECONDS));
        }

        return $ttl;
    }

    /**
     * Load the pending sign-in by its identifier from the write connection.
     *
     * @param  string  $id
     * @return ?\SineMacula\Laravel\Authentication\Models\PendingSignIn
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private static function load(string $id): ?PendingSignIn
    {
        $model = new PendingSignIn;

        $pending = WriteConnection::during($model, static fn (): mixed => WriteConnection::query($model->newQuery())->find($id));

        return $pending instanceof PendingSignIn ? $pending : null;
    }

    /**
     * Whether the pending sign-in is one waiting for a factor, of the guard,
     * unexpired, and holds the digest of the secret.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @param  string  $guard
     * @param  string  $secret
     * @param  \Carbon\CarbonImmutable  $now
     * @return bool
     */
    private static function isLive(PendingSignIn $pending, string $guard, #[\SensitiveParameter] string $secret, CarbonImmutable $now): bool
    {
        return RefreshTokenHasher::verify($secret, $pending->token_digest)
            && $pending->purpose === PendingSignIn::ADDITIONAL_FACTOR
            && $pending->guard   === $guard
            && $pending->expires_at->getTimestamp() > $now->getTimestamp();
    }

    /**
     * Reload the identity the pending sign-in recorded through the guard's
     * provider, when the provider returns that very owner.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function owner(PendingSignIn $pending, IdentityProvider $provider): ?Identity
    {
        $identity = $provider->retrieveById($pending->authenticatable_id);

        return $identity instanceof Identity
            && $identity instanceof Model
            && $identity->getMorphClass() === $pending->authenticatable_type
            && IdentifierCoercion::matches($identity->getKey(), $pending->authenticatable_id)
            ? $identity
            : null;
    }

    /**
     * Resolve the principal the pending sign-in recorded through the resolver's
     * hinted path, when it comes back as that principal and still belongs to
     * the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private static function principal(PendingSignIn $pending, Identity $identity, PrincipalResolver $resolver): ?Principal
    {
        $principal = $resolver->resolve($identity, $pending->principal_id);

        return $principal instanceof Principal
            && PrincipalReference::type($principal) === $pending->principal_type
            && IdentifierCoercion::matches($principal->getPrincipalIdentifier(), $pending->principal_id)
            && PinnedPrincipal::isOwnedBy($principal, $identity)
            ? $principal
            : null;
    }

    /**
     * Describe the live pending sign-in the token named.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @param  string  $secret
     * @param  string  $token
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private static function found(
        PendingSignIn $pending,
        #[\SensitiveParameter] string $secret,
        #[\SensitiveParameter] string $token,
        Identity $identity,
        Principal $principal,
    ): FoundPendingSignIn {
        $tenant = ActivationPolicy::activeTenant($principal);
        $device = self::provenDevice($pending, $identity, $principal);

        $factor = new PendingFactor(
            $token,
            $pending->guard,
            $identity,
            $principal,
            $tenant === false ? null : $tenant,
            $pending->sign_in_method,
            CarbonImmutable::instance($pending->expires_at),
            $device,
        );

        return new FoundPendingSignIn($pending, $secret, $factor, $device);
    }

    /**
     * The device the client proved it holds, when it is still the identity's
     * live session of the pending sign-in's guard for the principal, at the
     * digest it was proven against.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\PendingSignIn  $pending
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private static function provenDevice(PendingSignIn $pending, Identity $identity, Principal $principal): (EloquentDevice&Model)|null
    {
        $device = $pending->device_id === null ? null : DeviceLookup::find($pending->device_id);

        if ($device === null || !DeviceOwnership::isOwner($device, $identity) || !PrincipalReference::isRecordedOn($device, $principal)) {
            return null;
        }

        $proven = WriteConnection::during($device, static fn (): bool => $device->getGuard() === $pending->guard
            && $device->getRevokedAt()                                                       === null
            && $device->getRefreshKey() !== null
            && $device->getRefreshKey() === $pending->device_refresh_key);

        return $proven ? $device : null;
    }
}
