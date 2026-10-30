<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Jwt\DeviceLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * The sessions a bulk revocation ends: an identity's, or a principal's, with
 * the devices that hold them, the pending sign-ins that could still start one,
 * the "tokens valid after" cutoff that ends its access tokens issued without a
 * device, and, for an identity whose identifiers can be changed, its pending
 * identifier changes, which end with them.
 *
 * An identity's devices are those its `devices()` relation returns, of every
 * guard; a principal's are the configured device model's devices that record it
 * as their principal. Only an identity that implements `HasDevices` can hold a
 * device or a pending sign-in (the session service refuses to start a session
 * for any other), so a scope whose identity does not (access-only mode, where
 * the package's tables may not exist) touches neither and only moves its
 * cutoff, and an unsaved principal has neither to find. A principal's scope
 * ends no identifier change: the identity that requested one keeps its other
 * sessions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RevocationScope
{
    /**
     * Constructor.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  ?array{0: \Illuminate\Contracts\Database\Eloquent\Builder, 1: \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice}  $devices
     * @param  ?array<string, string>  $pendings
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter  $cutoff
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  list<string>  $changes
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function __construct(

        /** A query of the scope's devices, in any state, with their model, or `null` when it has none to find. */
        public ?array $devices,

        /** The columns and values that pick the scope's pending sign-ins, or `null` when it has none. */
        public ?array $pendings,

        /** The scope's "tokens valid after" holder, when it records one. */
        public ?HasTokensValidAfter $cutoff,

        /** The identity whose sessions end, or the principal's owner, when known. */
        public ?Identity $identity,

        /** The principal whose sessions end, for a principal's scope. */
        public ?Principal $principal,

        /** The tenant whose deactivation ends them, if that is why. */
        public ?Tenant $tenant = null,

        /** The keys of the identity's pending identifier changes that end with its sessions (see `PendingChanges::key()`); none for a principal's scope. */
        public array $changes = [],
    ) {}

    /**
     * Every session of the identity, through its `devices()` relation, read on
     * the write connection, and its pending identifier changes of the types
     * given, for an identity whose identifiers can be changed: a change link
     * needs no session, so one requested from a session that ends must end with
     * it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  list<string>  $changeTypes
     * @return self
     *
     * @throws \LogicException
     */
    public static function identity(Identity $identity, array $changeTypes = []): self
    {
        $devices  = $identity instanceof HasDevices ? IdentityDevices::query($identity) : null;
        $pendings = $identity instanceof HasDevices && $identity instanceof Model ? self::owner($identity) : null;
        $changes  = array_map(static fn (string $type): string => PendingChanges::key($identity, $type), $changeTypes);

        return new self($devices, $pendings, $identity instanceof HasTokensValidAfter ? $identity : null, $identity, null, changes: $changes);
    }

    /**
     * Every session acting as the principal, of the configured device model,
     * read on the write connection, with the tenant whose deactivation ends
     * them when that is why, and the principal's owning identity, read afresh
     * on the write connection (a 2D principal is its own). When that identity
     * does not implement `HasDevices`, no session acting as the principal can
     * hold a device or a pending sign-in, so none is looked for; when the owner
     * cannot be read, they are.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return self
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public static function principal(Principal $principal, ?Tenant $tenant = null): self
    {
        $owner    = self::ownerOf($principal);
        $id       = PrincipalReference::id($principal);
        $recorded = $id === null || ($owner !== null && !$owner instanceof HasDevices) ? null : ['principal_type' => PrincipalReference::type($principal), 'principal_id' => $id];
        $devices  = null;

        if ($recorded !== null) {

            $model = DeviceLookup::model();

            [$type, $key] = PrincipalReference::columns($model);

            $devices = [WriteConnection::query($model->newQuery())->where([$type => $recorded['principal_type'], $key => $recorded['principal_id']]), $model];
        }

        return new self(
            $devices,
            $recorded,
            $principal instanceof HasTokensValidAfter ? $principal : null,
            $owner,
            $principal,
            $tenant,
        );
    }

    /**
     * The same sessions with the cutoff left where it is, so the scope's
     * device-less access tokens keep working: how the request's own device-less
     * session is kept when its identity signs out everywhere else.
     *
     * @return self
     */
    public function keepingCutoff(): self
    {
        return new self($this->devices, $this->pendings, null, $this->identity, $this->principal, $this->tenant, $this->changes);
    }

    /**
     * The principal's owning identity, read through `WriteConnection::stored()`
     * so a relation set by whoever loaded it cannot stand in for the stored
     * owner, or `null` when it cannot be read: a `LogicException`, as
     * `ActsAsPrincipal` throws for a deleted owner.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function ownerOf(Principal $principal): ?Identity
    {
        if ($principal instanceof Identity) {
            return $principal;
        }

        try {
            return WriteConnection::stored($principal, static fn (Principal $stored): Identity => $stored->getIdentity());
        } catch (\LogicException) {
            return null;
        }
    }

    /**
     * The pending sign-in columns that pick the identity's, as the pending
     * sign-ins record their owner.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $identity
     * @return ?array<string, string>
     */
    private static function owner(Model $identity): ?array
    {
        $key = IdentifierCoercion::stringify($identity->getKey());

        return $key === null ? null : ['authenticatable_type' => $identity->getMorphClass(), 'authenticatable_id' => $key];
    }
}
