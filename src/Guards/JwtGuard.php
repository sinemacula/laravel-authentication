<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;

/**
 * Stateless JWT bearer-token guard.
 *
 * Reads `Authorization: Bearer <token>` from the active request,
 * decodes via `JwtTokenService`, validates payload claims, and binds
 * the resolved identity, principal, and (optional) device.
 *
 * Also exposes `refresh()` for refresh-credential exchange (REQ-03).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class JwtGuard extends AbstractGuard
{
    public function __construct(
        string $name,
        IdentityProvider $provider,
        PrincipalResolver $resolver,
        Dispatcher $events,
        Request $request,
        Timebox $timebox,

        /** Token service used to decode and issue JWTs. */
        protected JwtTokenService $tokens,
    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);
    }

    /**
     * Return the authenticated identity bound to the guard, resolving
     * it from the request's bearer token if necessary.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    public function user(): ?Identity
    {
        if ($this->identity !== null) {
            return $this->identity;
        }

        $token = $this->request->bearerToken();

        if ($token === null || $token === '') {
            return null;
        }

        $claims = $this->tokens->parse($token);

        if ($claims === null) {
            return null;
        }

        $sub = $claims['sub'] ?? null;

        if ($sub === null) {
            return null;
        }

        $user = $this->provider->retrieveById($sub);

        if (! $user instanceof Identity) {
            return null;
        }

        $principal = $this->resolver->resolve($user, $claims['pid'] ?? null);

        if (! $principal instanceof Principal || ! $principal->isActive()) {
            return null;
        }

        $device = $this->resolveDeviceFromHint($user, $claims['did'] ?? null);

        $this->setIdentity($user);
        $this->setPrincipal($principal);

        if ($device !== null) {
            $this->setDevice($device);
        }

        return $user;
    }

    /**
     * Exchange a refresh token for a new access token.
     *
     * Decodes the refresh token (ignoring `exp`), verifies the refresh
     * key against the stored device record, hydrates the contextual
     * lifecycle from the device's polymorphic authenticatable relation,
     * and issues a fresh access token. Dispatches `Refreshed` on success.
     *
     * @param  string $refreshToken The plaintext refresh token.
     * @return string|null The new access token, or null on any failure.
     */
    public function refresh(string $refreshToken): ?string
    {
        $claims = $this->tokens->parseAllowingExpired($refreshToken);

        if ($claims === null) {
            return null;
        }

        $deviceId          = $claims['did'] ?? null;
        $refreshKeyPayload = $claims['rk']  ?? null;

        if ($deviceId === null || ! is_string($refreshKeyPayload)) {
            return null;
        }

        $device = $this->findDeviceById($deviceId);

        if ($device === null || $device->getRefreshKey() !== $refreshKeyPayload) {
            return null;
        }

        if (! $device instanceof Model) {
            return null;
        }

        /** @var \SineMacula\Laravel\Authentication\Contracts\Identity|null $identity */
        $identity = $device->getRelationValue('authenticatable');

        if (! $identity instanceof Identity) {
            return null;
        }

        $principal = $this->resolver->resolve($identity);

        if (! $principal instanceof Principal) {
            return null;
        }

        $this->setIdentity($identity);
        $this->setPrincipal($principal);
        $this->setDevice($device);

        $this->events->dispatch(new Refreshed($this->name, $identity));

        return $this->tokens->issueAccessToken($identity, $principal, $device);
    }

    /**
     * Resolve a device record for the identity from a hint (typically a
     * device id from the access-token payload). Returns null when the
     * identity does not implement `HasDevices` or the device is not found.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity $identity The identity whose devices to query.
     * @param  mixed                                                 $hint     The device identifier hint from the token payload.
     * @return \SineMacula\Laravel\Authentication\Contracts\Device|null
     */
    protected function resolveDeviceFromHint(Identity $identity, mixed $hint): ?Device
    {
        if ($hint === null || ! $identity instanceof HasDevices) {
            return null;
        }

        $device = $identity->devices()->find($hint);

        return $device instanceof Device ? $device : null;
    }

    /**
     * Look up a device by id through the configured device model class.
     *
     * @param  mixed $id The device identifier to look up.
     * @return \SineMacula\Laravel\Authentication\Contracts\Device|null
     */
    protected function findDeviceById(mixed $id): ?Device
    {
        $class = (string) config('laravel-authentication.device.model');

        if ($class === '') {
            return null;
        }

        /** @var \Illuminate\Database\Eloquent\Model $model */
        $model = new $class;

        $device = $model->newQuery()->find($id);

        return $device instanceof Device ? $device : null;
    }
}
